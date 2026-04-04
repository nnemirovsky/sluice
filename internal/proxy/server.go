package proxy

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"

	"github.com/nemirovsky/sluice/internal/audit"
	"github.com/nemirovsky/sluice/internal/channel"
	"github.com/nemirovsky/sluice/internal/policy"
	"github.com/nemirovsky/sluice/internal/store"
	"github.com/nemirovsky/sluice/internal/vault"
)

// dnsTimeout bounds how long a single DNS lookup can block. The go-socks5
// library passes context.Background() into the resolver, so we cannot rely
// on external cancellation. This timeout prevents a stuck system resolver
// from holding a request goroutine indefinitely.
const dnsTimeout = 10 * time.Second

// connectTimeout bounds how long a single outbound TCP connect can block.
// Without this, a client can point the proxy at a black-holed IP and hold
// a goroutine/socket until the kernel TCP timeout expires (typically 2+
// minutes on Linux). This limits the resource impact of such requests.
const connectTimeout = 30 * time.Second

// Config holds configuration for creating a new SOCKS5 proxy server.
type Config struct {
	ListenAddr    string
	Policy        *policy.Engine
	Audit         *audit.FileLogger
	Broker        *channel.Broker
	Provider      vault.Provider           // nil = no credential injection
	Resolver      *vault.BindingResolver   // nil = no credential injection
	VaultDir      string                   // CA cert storage dir (defaults to ~/.sluice)
	Store         *store.Store             // nil = in-memory only (no persistence)
	WSBlockRules    []WSBlockRuleConfig      // WebSocket content deny rules
	WSRedactRules   []WSRedactRuleConfig     // WebSocket content redact rules
	QUICBlockRules  []QUICBlockRuleConfig    // QUIC/HTTP3 content deny rules
	QUICRedactRules []QUICRedactRuleConfig   // QUIC/HTTP3 content redact rules
	DNSResolver     string                   // upstream DNS resolver for intercepted queries (default: 8.8.8.8:53)
}

// Server wraps a SOCKS5 server with policy enforcement and audit logging.
type Server struct {
	listener       net.Listener
	socks          *socks5.Server
	rules          *policyRuleSet
	dnsResolver    *policyResolver
	injector       *Injector
	injectorLn     net.Listener
	sshJump        *SSHJumpHost
	mailProxy      *MailProxy
	udpRelay       *UDPRelay
	dnsInterceptor *DNSInterceptor
	quicProxy      *QUICProxy
	resolver       atomic.Pointer[vault.BindingResolver]
	closed         atomic.Bool
	serving        atomic.Bool
	activeConns    sync.WaitGroup
}

type contextKey string

const ctxKeyProtocol       contextKey = "protocol"
const ctxKeyEngine         contextKey = "engine"
const ctxKeyFallbackAddrs  contextKey = "fallbackAddrs"
const ctxKeyFQDN           contextKey = "fqdn"

// ProtocolFromContext retrieves the detected protocol from the request context.
func ProtocolFromContext(ctx context.Context) Protocol {
	if v, ok := ctx.Value(ctxKeyProtocol).(Protocol); ok {
		return v
	}
	return ProtoGeneric
}

// isPrivateIP checks whether an IP is in a private, loopback, link-local,
// or unspecified range. These addresses should not be reachable via DNS
// rebinding of allow-listed hostnames unless explicitly allowed by policy.
func isPrivateIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

// policyResolver performs DNS resolution only for destinations that could be
// allowed by policy. Definitely-denied destinations return nil IP (no DNS
// lookup) to prevent leaks. For potentially-allowed destinations, DNS failures
// return an error so go-socks5 sends a hostUnreachable reply instead of the
// ruleFailure that would result from failing inside Allow().
type policyResolver struct {
	engine *atomic.Pointer[policy.Engine]
	audit  *audit.FileLogger
	broker *channel.Broker
}

func (r *policyResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	dest := strings.TrimRight(name, ".")

	eng := r.engine.Load()
	// Store engine snapshot in context so Allow() evaluates against the
	// same policy version, preventing a SIGHUP reload from splitting a
	// single request across two different policy snapshots.
	ctx = context.WithValue(ctx, ctxKeyEngine, eng)
	// Only treat Ask rules as potentially-allowed when an approval broker
	// is configured. Without a broker, Ask verdicts become Deny, so
	// resolving DNS would leak queries for destinations that will be denied.
	includeAsk := r.broker != nil
	if !eng.CouldBeAllowed(dest, includeAsk) {
		// Definitely denied on all ports: skip DNS to prevent leaks.
		// Allow() will deny the connection with ruleFailure.
		return ctx, nil, nil
	}

	// Destination might be allowed: resolve DNS. The context from
	// go-socks5 is context.Background() and is never cancelled, so we
	// add our own timeout to bound stalled system resolver lookups.
	// Failures return an error so go-socks5 sends hostUnreachable
	// (more accurate than ruleFailure).
	dnsCtx, dnsCancel := context.WithTimeout(ctx, dnsTimeout)
	defer dnsCancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(dnsCtx, dest)
	if err != nil {
		log.Printf("[DENY] DNS resolution failed for %s: %v", dest, err)
		if r.audit != nil {
			if logErr := r.audit.Log(audit.Event{
				Destination: dest,
				Verdict:     policy.Deny.String(),
				Reason:      "dns resolution failed",
			}); logErr != nil {
				log.Printf("audit log write error: %v", logErr)
			}
		}
		return ctx, nil, fmt.Errorf("resolve %s: %w", dest, err)
	}
	if len(addrs) == 0 {
		log.Printf("[DENY] DNS resolution returned no addresses for %s", dest)
		if r.audit != nil {
			if logErr := r.audit.Log(audit.Event{
				Destination: dest,
				Verdict:     policy.Deny.String(),
				Reason:      "dns resolution failed",
			}); logErr != nil {
				log.Printf("audit log write error: %v", logErr)
			}
		}
		return ctx, nil, fmt.Errorf("resolve %s: no addresses found", dest)
	}

	// The go-socks5 NameResolver interface returns a single IP, so we
	// pass the first address and store any remaining addresses in the
	// context as fallbacks. The custom Dial function tries them in order
	// if the primary address is unreachable, providing resilience on
	// dual-stack hosts where the preferred address family may be unusable.
	// The system resolver already applies RFC 6724 destination address
	// selection, so addrs[0] is the best first choice.
	if len(addrs) > 1 {
		fallback := make([]net.IP, len(addrs)-1)
		for i, a := range addrs[1:] {
			fallback[i] = a.IP
		}
		ctx = context.WithValue(ctx, ctxKeyFallbackAddrs, fallback)
	}
	return ctx, addrs[0].IP, nil
}

type policyRuleSet struct {
	engine   *atomic.Pointer[policy.Engine]
	reloadMu *sync.Mutex // serializes engine swaps and dynamic rule mutations
	audit    *audit.FileLogger
	broker   *channel.Broker
	store    *store.Store
}

func (r *policyRuleSet) Allow(ctx context.Context, req *socks5.Request) (context.Context, bool) {
	// BIND is not implemented; ASSOCIATE is handled by go-socks5's built-in
	// UDP relay. Return true for both so go-socks5 reaches its own handler
	// instead of sending ruleFailure. Per-datagram policy enforcement for
	// UDP ASSOCIATE will be added via a custom associate handler.
	if req.Command != statute.CommandConnect {
		return ctx, true
	}

	dest := req.DestAddr.FQDN
	if dest == "" {
		if req.DestAddr.IP != nil {
			dest = req.DestAddr.IP.String()
		} else {
			return ctx, false
		}
	}
	// Strip trailing dot from FQDN to canonicalize DNS names.
	// In DNS, "example.com." and "example.com" are equivalent.
	// Without this, a SOCKS5 client can bypass deny rules by
	// appending a dot to the hostname.
	dest = strings.TrimRight(dest, ".")
	port := req.DestAddr.Port

	// Use the engine snapshot from Resolve() (stored in context) to ensure
	// consistent policy evaluation within a single request. For IP-based
	// requests where Resolve() was not called, load fresh from the pointer.
	eng, _ := ctx.Value(ctxKeyEngine).(*policy.Engine)
	if eng == nil {
		eng = r.engine.Load()
	}
	verdict := eng.Evaluate(dest, port)

	// Determine the effective outcome.
	allowed := false
	effectiveVerdict := verdict
	var reason string
	switch verdict {
	case policy.Allow:
		allowed = true
	case policy.Ask:
		if r.broker == nil {
			effectiveVerdict = policy.Deny
			reason = "ask treated as deny (no approval broker)"
			log.Printf("[ASK->DENY] %s:%d (no approval broker)", dest, port)
		} else {
			log.Printf("[ASK] %s:%d (waiting for Telegram approval)", dest, port)
			timeout := time.Duration(eng.TimeoutSec) * time.Second
			resp, err := r.broker.Request(dest, port, timeout)
			if err != nil {
				effectiveVerdict = policy.Deny
				reason = fmt.Sprintf("approval timeout: %v", err)
				log.Printf("[ASK->DENY] %s:%d (timeout: %v)", dest, port, err)
			} else {
				switch resp {
				case channel.ResponseAllowOnce:
					allowed = true
					effectiveVerdict = policy.Allow
					reason = "user approved once"
					log.Printf("[ASK->ALLOW] %s:%d (user approved once)", dest, port)
				case channel.ResponseAlwaysAllow:
					allowed = true
					effectiveVerdict = policy.Allow
					reason = "user approved always"
					log.Printf("[ASK->ALLOW+SAVE] %s:%d (user approved always)", dest, port)
					// Hold reloadMu to prevent a concurrent SIGHUP from swapping
					// the engine between the store write and recompile.
					r.reloadMu.Lock()
					func() {
						defer r.reloadMu.Unlock()
						if r.store != nil {
							if _, storeErr := r.store.AddRule("allow", store.RuleOpts{Destination: dest, Ports: []int{port}, Source: "approval"}); storeErr != nil {
								log.Printf("[WARN] failed to persist allow rule for %s:%d: %v", dest, port, storeErr)
							}
							if newEng, recompErr := policy.LoadFromStore(r.store); recompErr != nil {
								log.Printf("[WARN] failed to recompile engine after always-allow: %v", recompErr)
							} else if valErr := newEng.Validate(); valErr != nil {
								log.Printf("[WARN] engine validation failed after always-allow: %v", valErr)
							} else {
								r.engine.Store(newEng)
							}
						} else {
							if err := r.engine.Load().AddDynamicAllow(dest, port); err != nil { //nolint:staticcheck // backward compat fallback when no store
								log.Printf("[WARN] failed to add dynamic allow rule for %s:%d: %v", dest, port, err)
							}
						}
					}()
				default:
					effectiveVerdict = policy.Deny
					reason = "user denied"
					log.Printf("[ASK->DENY] %s:%d (user denied)", dest, port)
				}
			}
		}
	}

	// DNS rebinding check for FQDN connections. The policyResolver
	// already resolved the IP, so we verify it is not restricted.
	if allowed && req.DestAddr.FQDN != "" && req.DestAddr.IP != nil {
		resolvedIP := req.DestAddr.IP.String()
		if eng.IsRestricted(resolvedIP, port) {
			allowed = false
			effectiveVerdict = policy.Deny
			reason = fmt.Sprintf("resolved IP %s is restricted", resolvedIP)
			log.Printf("[DENY] %s resolved to restricted IP %s", req.DestAddr.FQDN, resolvedIP)
		} else if isPrivateIP(req.DestAddr.IP) && eng.Evaluate(resolvedIP, port) != policy.Allow {
			allowed = false
			effectiveVerdict = policy.Deny
			reason = fmt.Sprintf("resolved IP %s is private and not allowed by policy", resolvedIP)
			log.Printf("[DENY] %s resolved to private IP %s (DNS rebinding protection)", req.DestAddr.FQDN, resolvedIP)
		}
	}

	// Filter fallback addresses through the same rebinding/policy checks
	// so the Dial function only tries addresses that would be allowed.
	if allowed && req.DestAddr.FQDN != "" {
		if fallbacks, ok := ctx.Value(ctxKeyFallbackAddrs).([]net.IP); ok {
			approved := make([]net.IP, 0, len(fallbacks))
			for _, ip := range fallbacks {
				ipStr := ip.String()
				if eng.IsRestricted(ipStr, port) {
					continue
				}
				if isPrivateIP(ip) && eng.Evaluate(ipStr, port) != policy.Allow {
					continue
				}
				approved = append(approved, ip)
			}
			ctx = context.WithValue(ctx, ctxKeyFallbackAddrs, approved)
		}
	}

	// Single audit entry reflecting the final outcome.
	if r.audit != nil {
		if err := r.audit.Log(audit.Event{
			Destination: dest,
			Port:        port,
			Verdict:     effectiveVerdict.String(),
			Reason:      reason,
		}); err != nil {
			log.Printf("audit log write error: %v", err)
		}
	}

	if allowed {
		proto := DetectProtocol(port)
		ctx = context.WithValue(ctx, ctxKeyProtocol, proto)
		ctx = context.WithValue(ctx, ctxKeyFQDN, dest)
	}
	return ctx, allowed
}

// New creates a new SOCKS5 proxy server bound to the configured listen address.
func New(cfg Config) (*Server, error) {
	if cfg.Policy == nil {
		return nil, fmt.Errorf("policy engine is required")
	}
	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}

	srv := &Server{listener: ln}

	// Initialize credential injection handlers when a vault provider is
	// configured. The resolver may be nil at startup (no bindings yet) and
	// set later via StoreResolver after SIGHUP or Telegram mutations.
	if cfg.Resolver != nil {
		srv.resolver.Store(cfg.Resolver)
	}
	if cfg.Provider != nil {
		injErr := srv.setupInjection(cfg, ln)
		if injErr != nil {
			// When bindings exist (resolver is set), injection infrastructure
			// is required. Hard-fail so the operator fixes the issue.
			if cfg.Resolver != nil {
				_ = ln.Close()
				return nil, injErr
			}
			// No bindings yet. Degrade to policy-only mode so network
			// governance still works. Injection can be enabled by fixing
			// the underlying issue (e.g. CA dir permissions) and restarting.
			log.Printf("credential injection disabled (no bindings): %v", injErr)
		}
	}

	enginePtr := new(atomic.Pointer[policy.Engine])
	enginePtr.Store(cfg.Policy)
	reloadMu := new(sync.Mutex)

	rules := &policyRuleSet{engine: enginePtr, reloadMu: reloadMu, audit: cfg.Audit, broker: cfg.Broker, store: cfg.Store}
	dnsRes := &policyResolver{engine: enginePtr, audit: cfg.Audit, broker: cfg.Broker}
	srv.rules = rules
	srv.dnsResolver = dnsRes

	// Create UDP relay and DNS interceptor for UDP ASSOCIATE sessions.
	srv.udpRelay = NewUDPRelay(enginePtr, cfg.Audit)
	srv.dnsInterceptor = NewDNSInterceptor(enginePtr, cfg.Audit, cfg.DNSResolver)

	srv.socks = socks5.NewServer(
		socks5.WithRule(rules),
		socks5.WithResolver(dnsRes),
		socks5.WithDial(srv.dial),
		socks5.WithAssociateHandle(srv.handleAssociate),
	)

	return srv, nil
}

// setupInjection initializes the credential injection infrastructure (HTTPS
// MITM, SSH jump host, mail proxy). Returns an error if any component fails.
// The caller decides whether the error is fatal based on whether bindings exist.
func (s *Server) setupInjection(cfg Config, mainLn net.Listener) error {
	vaultDir := cfg.VaultDir
	if vaultDir == "" {
		home, homeErr := os.UserHomeDir()
		if homeErr != nil {
			return fmt.Errorf("determine home dir for CA: %w", homeErr)
		}
		vaultDir = filepath.Join(home, ".sluice")
	}
	caCert, _, caErr := LoadOrCreateCA(vaultDir)
	if caErr != nil {
		return fmt.Errorf("load CA: %w", caErr)
	}

	certPath := filepath.Join(vaultDir, "ca-cert.pem")
	if expiring, expiryErr := IsCACertExpiring(certPath, 30*24*time.Hour); expiryErr == nil && expiring {
		log.Printf("WARNING: CA certificate at %s expires within 30 days. Delete and restart to regenerate.", certPath)
	}

	// Generate a random auth token so only our SOCKS5 dial function
	// can use the injector listener. Without this, any local process
	// that discovers the port could bypass policy and audit logging.
	tokenBytes := make([]byte, 16)
	if _, tokenErr := rand.Read(tokenBytes); tokenErr != nil {
		return fmt.Errorf("generate injector auth token: %w", tokenErr)
	}
	authToken := hex.EncodeToString(tokenBytes)

	// Create WebSocket proxy for frame-level inspection when configured.
	var wsProxy *WSProxy
	if len(cfg.WSBlockRules) > 0 || len(cfg.WSRedactRules) > 0 {
		var wsErr error
		wsProxy, wsErr = NewWSProxy(cfg.Provider, &s.resolver, cfg.WSBlockRules, cfg.WSRedactRules)
		if wsErr != nil {
			return fmt.Errorf("create ws proxy: %w", wsErr)
		}
	} else {
		// Create WSProxy with empty rules for phantom token replacement.
		wsProxy, _ = NewWSProxy(cfg.Provider, &s.resolver, nil, nil)
	}

	s.injector = NewInjector(cfg.Provider, &s.resolver, caCert, authToken, wsProxy)
	injLn, injErr := net.Listen("tcp", "127.0.0.1:0")
	if injErr != nil {
		return fmt.Errorf("injector listener: %w", injErr)
	}
	s.injectorLn = injLn
	go http.Serve(injLn, s.injector.Proxy) //nolint:errcheck // best-effort

	// SSH jump host for credential-injected SSH connections.
	hostKey, hkErr := GenerateSSHHostKey()
	if hkErr != nil {
		_ = injLn.Close()
		s.injectorLn = nil
		s.injector = nil
		return fmt.Errorf("generate SSH host key: %w", hkErr)
	}
	s.sshJump = NewSSHJumpHost(cfg.Provider, hostKey)

	// Mail proxy for IMAP/SMTP credential injection. Pass the CA cert
	// so implicit TLS ports (993, 465) can be handled via TLS MITM.
	s.mailProxy = NewMailProxy(cfg.Provider, &caCert)

	// QUIC proxy for HTTP/3 MITM credential injection over UDP.
	qp, qpErr := NewQUICProxy(caCert, cfg.Provider, &s.resolver, cfg.Audit, cfg.QUICBlockRules, cfg.QUICRedactRules)
	if qpErr != nil {
		log.Printf("QUIC proxy disabled: %v", qpErr)
	} else {
		s.quicProxy = qp
		go func() {
			if listenErr := qp.ListenAndServe("127.0.0.1:0"); listenErr != nil {
				log.Printf("[QUIC] listener stopped: %v", listenErr)
			}
		}()
	}

	log.Printf("credential injection enabled (%s)", cfg.Provider.Name())
	return nil
}

// dial is the custom dialer for go-socks5. When a credential binding matches
// the destination, the connection is routed through the appropriate injection
// handler (HTTPS MITM, SSH jump host, or mail proxy). Otherwise it falls
// through to a direct TCP connection with DNS fallback support.
func (s *Server) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if r := s.resolver.Load(); r != nil {
		fqdn, _ := ctx.Value(ctxKeyFQDN).(string)
		if fqdn != "" {
			_, portStr, _ := net.SplitHostPort(addr)
			port, _ := strconv.Atoi(portStr)

			proto := ProtocolFromContext(ctx)
			// Use protocol-aware resolution so the correct binding is
			// selected when multiple bindings exist for the same host:port
			// with different protocols (e.g. one for SSH, one for HTTPS).
			binding, ok := r.ResolveForProtocol(fqdn, port, string(proto))
			if !ok {
				// No protocol-specific or protocol-agnostic binding
				// matched. Fall back to any dest+port binding and adopt
				// its protocol when unambiguous. ResolveProtocolHint
				// scans ALL bindings for this dest+port and returns false
				// when multiple single-protocol bindings disagree,
				// preventing order-dependent protocol selection.
				binding, ok = r.Resolve(fqdn, port)
				if ok && len(binding.Protocols) == 1 {
					if hint, hok := r.ResolveProtocolHint(fqdn, port); hok {
						proto = Protocol(hint)
					}
				}
			}
			// When protocol is still generic (non-standard port) and
			// resolution returned a protocol-agnostic binding, check
			// if a single-protocol binding exists for this dest+port.
			// Without this, the agnostic fallback from ResolveForProtocol
			// masks protocol-specific bindings and the connection falls
			// through to direct dial, bypassing the injector.
			if ok && proto == ProtoGeneric && len(binding.Protocols) == 0 {
				if hint, hok := r.ResolveProtocolHint(fqdn, port); hok {
					proto = Protocol(hint)
					if specific, sok := r.ResolveForProtocol(fqdn, port, hint); sok {
						binding = specific
					}
				}
			}
			if ok {
				// hostAddr uses the FQDN for TLS SNI and SSH known_hosts
				// verification. addr (the go-socks5 dial target) uses the
				// policy-approved resolved IP for the actual TCP connection,
				// preventing DNS rebinding between policy evaluation and dial.
				hostAddr := net.JoinHostPort(fqdn, portStr)

				// Build address list from primary + policy-approved fallbacks
				// so injection handlers have the same dual-stack resilience
				// as the non-injected direct connection path.
				dialAddrs := []string{addr}
				if fallbacks, ok := ctx.Value(ctxKeyFallbackAddrs).([]net.IP); ok {
					for _, ip := range fallbacks {
						dialAddrs = append(dialAddrs, net.JoinHostPort(ip.String(), portStr))
					}
				}

				switch proto {
				case ProtoHTTP, ProtoHTTPS:
					if s.injector != nil {
						// Pin the policy-approved IPs so goproxy's
						// transport dials them instead of re-resolving.
						// Each connection gets a unique pin ID to avoid
						// races between concurrent same-host connections.
						ips := make([]string, len(dialAddrs))
						for i, a := range dialAddrs {
							ip, _, _ := net.SplitHostPort(a)
							ips[i] = ip
						}
						pinID := generatePinID()
						s.injector.PinIPs(pinID, ips)
						conn, err := dialThroughInjector(s.injectorLn.Addr().String(), fqdn, port, s.injector.authToken, pinID)
						if err != nil {
							s.injector.UnpinIPs(pinID)
							return nil, err
						}
						return &pinnedConn{Conn: conn, injector: s.injector, pinID: pinID}, nil
					}
				case ProtoSSH:
					if s.sshJump != nil {
						return dialWithHandler(func(agentConn net.Conn, ready chan<- error) {
							if err := s.sshJump.HandleConnection(agentConn, dialAddrs, hostAddr, binding, ready); err != nil {
								log.Printf("[SSH] handler error: %v", err)
							}
						})
					}
				case ProtoIMAP, ProtoSMTP:
					if s.mailProxy != nil {
						return dialWithHandler(func(agentConn net.Conn, ready chan<- error) {
							if err := s.mailProxy.HandleConnection(agentConn, dialAddrs, hostAddr, binding, proto, ready); err != nil {
								log.Printf("[MAIL] handler error: %v", err)
							}
						})
					}
				}
			}
		}
	}

	// Route unbound HTTP/HTTPS through the injector when available so
	// phantom tokens are stripped from requests to hosts without bindings.
	// Without this, requests bypassing the binding-match block above
	// would go direct and leak SLUICE_PHANTOM:* tokens upstream.
	if s.injector != nil {
		_, portStr, _ := net.SplitHostPort(addr)
		port, _ := strconv.Atoi(portStr)
		proto := DetectProtocol(port)
		if proto == ProtoHTTP || proto == ProtoHTTPS {
			fqdn, _ := ctx.Value(ctxKeyFQDN).(string)
			if fqdn == "" {
				host, _, _ := net.SplitHostPort(addr)
				fqdn = host
			}
			ips := []string{}
			if ip, _, err := net.SplitHostPort(addr); err == nil {
				ips = append(ips, ip)
			}
			if fallbacks, ok := ctx.Value(ctxKeyFallbackAddrs).([]net.IP); ok {
				for _, ip := range fallbacks {
					ips = append(ips, ip.String())
				}
			}
			pinID := generatePinID()
			s.injector.PinIPs(pinID, ips)
			conn, err := dialThroughInjector(s.injectorLn.Addr().String(), fqdn, port, s.injector.authToken, pinID)
			if err != nil {
				s.injector.UnpinIPs(pinID)
				// Fall through to direct connection below.
			} else {
				return &pinnedConn{Conn: conn, injector: s.injector, pinID: pinID}, nil
			}
		}
	}

	// No credential binding or unsupported protocol: direct connection.
	d := &net.Dialer{Timeout: connectTimeout}
	conn, err := d.DialContext(ctx, network, addr)
	if err == nil {
		return conn, nil
	}
	// Try policy-approved fallback addresses from DNS resolution.
	fallbacks, _ := ctx.Value(ctxKeyFallbackAddrs).([]net.IP)
	if len(fallbacks) == 0 {
		return nil, err
	}
	_, portStr, splitErr := net.SplitHostPort(addr)
	if splitErr != nil {
		return nil, err
	}
	for _, ip := range fallbacks {
		fbAddr := net.JoinHostPort(ip.String(), portStr)
		if fbConn, fbErr := d.DialContext(ctx, network, fbAddr); fbErr == nil {
			return fbConn, nil
		}
	}
	return nil, err
}

// dialThroughInjector connects to the local goproxy MITM listener and
// establishes an HTTP CONNECT tunnel for the target host. The authToken
// is included as a header so the injector can verify the request
// originated from the SOCKS5 proxy rather than an unauthorized local process.
// The pinID identifies the per-connection pinned IPs for DNS rebinding protection.
func dialThroughInjector(injectorAddr, host string, port int, authToken, pinID string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", injectorAddr, connectTimeout)
	if err != nil {
		return nil, fmt.Errorf("connect to injector: %w", err)
	}

	target := net.JoinHostPort(host, strconv.Itoa(port))
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nX-Sluice-Auth: %s\r\nX-Sluice-Pin: %s\r\n\r\n", target, target, authToken, pinID)
	if _, wErr := io.WriteString(conn, req); wErr != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("send CONNECT: %w", wErr)
	}

	br := bufio.NewReader(conn)
	resp, rErr := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if rErr != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("read CONNECT response: %w", rErr)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		return nil, fmt.Errorf("CONNECT rejected: %s", resp.Status)
	}

	// If the buffered reader consumed bytes past the HTTP response headers,
	// wrap the connection so those bytes are read first.
	if br.Buffered() > 0 {
		return &bufferedConn{Reader: br, Conn: conn}, nil
	}
	return conn, nil
}

// handleAssociate is the custom SOCKS5 UDP ASSOCIATE handler registered via
// WithAssociateHandle. It creates a UDP listener, replies with its address,
// then dispatches datagrams to the DNSInterceptor (port 53) or UDPRelay
// (all other ports). The handler blocks until the TCP control connection
// closes, at which point all UDP sessions are cleaned up.
func (s *Server) handleAssociate(ctx context.Context, writer io.Writer, request *socks5.Request) error {
	// Bind a UDP listener on the same IP as the TCP connection.
	tcpAddr, ok := request.LocalAddr.(*net.TCPAddr)
	if !ok {
		if err := socks5.SendReply(writer, statute.RepServerFailure, nil); err != nil {
			return fmt.Errorf("send reply: %w", err)
		}
		return fmt.Errorf("local address is not TCP: %T", request.LocalAddr)
	}
	udpAddr := &net.UDPAddr{IP: tcpAddr.IP, Port: 0}
	bindLn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		if err := socks5.SendReply(writer, statute.RepServerFailure, nil); err != nil {
			return fmt.Errorf("send reply: %w", err)
		}
		return fmt.Errorf("listen udp: %w", err)
	}

	// Tell the client where to send UDP datagrams.
	if err := socks5.SendReply(writer, statute.RepSuccess, bindLn.LocalAddr()); err != nil {
		bindLn.Close()
		return fmt.Errorf("send reply: %w", err)
	}

	// Track upstream UDP sessions for non-DNS traffic.
	var mu sync.Mutex
	sessions := make(map[string]*udpSession)

	// Ensure bindLn is closed exactly once regardless of which goroutine
	// exits first (dispatch loop vs TCP control connection reader).
	var closeBindOnce sync.Once
	closeBind := func() { closeBindOnce.Do(func() { bindLn.Close() }) }

	// Start the datagram dispatch loop in a goroutine.
	go func() {
		defer func() {
			mu.Lock()
			for _, sess := range sessions {
				if s.quicProxy != nil {
					s.quicProxy.UnregisterExpectedHost(sess.upstream.LocalAddr().String())
				}
				sess.upstream.Close()
			}
			mu.Unlock()
			closeBind()
		}()

		buf := make([]byte, 65535)
		for {
			bindLn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, srcAddr, readErr := bindLn.ReadFrom(buf)
			if readErr != nil {
				if ne, ok := readErr.(net.Error); ok && ne.Timeout() {
					// Clean up expired sessions on timeout.
					mu.Lock()
					now := time.Now()
					for key, sess := range sessions {
						if now.Sub(sess.lastSeen) > udpSessionTimeout {
							if s.quicProxy != nil {
								s.quicProxy.UnregisterExpectedHost(sess.upstream.LocalAddr().String())
							}
							sess.upstream.Close()
							delete(sessions, key)
						}
					}
					mu.Unlock()
					continue
				}
				return
			}

			// Validate that the source matches the ASSOCIATE request's client.
			clientAddr, clientOK := request.RemoteAddr.(*net.TCPAddr)
			if !clientOK {
				continue
			}
			udpSrc, srcOK := srcAddr.(*net.UDPAddr)
			if !srcOK {
				continue
			}
			// Per RFC 1928: if the client specified 0.0.0.0:0, accept from any
			// source IP that matches the TCP client.
			if !request.DestAddr.IP.IsUnspecified() && !request.DestAddr.IP.Equal(udpSrc.IP) {
				continue
			}
			if request.DestAddr.Port != 0 && request.DestAddr.Port != udpSrc.Port {
				continue
			}
			// Also verify the source IP matches the TCP control connection's
			// remote IP to prevent other hosts from injecting datagrams.
			if !clientAddr.IP.Equal(udpSrc.IP) {
				continue
			}

			dest, port, payload, parseErr := ParseSOCKS5UDPHeader(buf[:n])
			if parseErr != nil {
				log.Printf("[UDP] invalid datagram from %s: %v", srcAddr, parseErr)
				continue
			}

			// DNS interception: port 53 traffic goes to the DNS interceptor.
			if port == 53 && s.dnsInterceptor != nil {
				resp, dnsErr := s.dnsInterceptor.HandleQuery(payload)
				if dnsErr != nil {
					log.Printf("[DNS] query handling error: %v", dnsErr)
					continue
				}
				// Wrap DNS response in SOCKS5 UDP header.
				dstIP := net.ParseIP(dest)
				if dstIP == nil {
					// Domain name destination: resolve for response header.
					addrs, resolveErr := net.LookupIP(dest)
					if resolveErr != nil || len(addrs) == 0 {
						log.Printf("[DNS] cannot resolve %s for response header: %v", dest, resolveErr)
						continue
					}
					dstIP = addrs[0]
				}
				respDatagram := BuildSOCKS5UDPResponse(dstIP, port, resp)
				if _, writeErr := bindLn.WriteTo(respDatagram, srcAddr); writeErr != nil {
					log.Printf("[DNS] write response to client: %v", writeErr)
				}
				continue
			}

			// QUIC interception: route packets to QUICProxy for HTTP/3 MITM
			// credential injection. Check existing sessions first so
			// short-header packets (used after handshake) are routed
			// correctly. Only use IsQUICPacket to decide whether to
			// CREATE a new session (it only matches long-header initials).
			if s.quicProxy != nil && isHTTPSPort(port) {
				sessionKey := "quic:" + dest + ":" + strconv.Itoa(port)
				mu.Lock()
				sess, exists := sessions[sessionKey]
				if exists {
					sess.lastSeen = time.Now()
				}
				mu.Unlock()

				if exists {
					quicAddr := s.quicProxy.Addr()
					if quicAddr == nil {
						log.Printf("[QUIC] proxy not ready, dropping datagram for %s:%d", dest, port)
						continue
					}
					if _, writeErr := sess.upstream.WriteTo(payload, quicAddr); writeErr != nil {
						log.Printf("[QUIC] write to proxy: %v", writeErr)
					}
					continue
				}

				if IsQUICPacket(payload) {
					quicAddr := s.quicProxy.Addr()
					if quicAddr != nil {
						// Evaluate policy using QUIC-specific matching so rules
						// with protocols = ["quic"] are honored.
						verdict := s.udpRelay.engine.Load().EvaluateQUIC(dest, port)
						if verdict != policy.Allow {
							if s.udpRelay.audit != nil {
								if logErr := s.udpRelay.audit.Log(audit.Event{
									Destination: dest,
									Port:        port,
									Protocol:    "quic",
									Verdict:     "deny",
									Reason:      "quic denied by policy",
								}); logErr != nil {
									log.Printf("audit log write error: %v", logErr)
								}
							}
							continue
						}

						upstream, listenErr := net.ListenPacket("udp", "127.0.0.1:0")
						if listenErr != nil {
							log.Printf("[QUIC] create upstream for %s: %v", sessionKey, listenErr)
							continue
						}
						// Register expected host so the QUIC proxy can verify
						// that the TLS SNI matches the policy-checked destination.
						s.quicProxy.RegisterExpectedHost(upstream.LocalAddr().String(), dest)
						mu.Lock()
						sess = &udpSession{upstream: upstream, lastSeen: time.Now()}
						sessions[sessionKey] = sess
						mu.Unlock()
						// Use the original destination for SOCKS5 response headers
						// since the QUIC proxy is local and its address would be
						// meaningless to the client.
						origDst := &net.UDPAddr{IP: net.ParseIP(dest), Port: port}
						if origDst.IP == nil {
							// Domain destination: resolve for response header.
							addrs, resolveErr := net.LookupIP(dest)
							if resolveErr == nil && len(addrs) > 0 {
								origDst.IP = addrs[0]
							} else {
								origDst.IP = net.IPv4zero
							}
						}
						go s.relayQUICResponses(upstream, bindLn, srcAddr, origDst)

						if _, writeErr := sess.upstream.WriteTo(payload, quicAddr); writeErr != nil {
							log.Printf("[QUIC] write to proxy: %v", writeErr)
						}
						continue
					}
					// QUICProxy not yet listening, fall through to normal UDP handling.
				}
			}

			// General UDP: evaluate policy via UDPRelay.
			verdict := s.udpRelay.evaluateUDP(dest, port)
			if verdict != policy.Allow {
				if s.udpRelay.audit != nil {
					if logErr := s.udpRelay.audit.Log(audit.Event{
						Destination: dest,
						Port:        port,
						Protocol:    "udp",
						Verdict:     "deny",
						Reason:      "udp denied",
					}); logErr != nil {
						log.Printf("audit log write error: %v", logErr)
					}
				}
				continue
			}

			// Relay allowed datagram to upstream.
			dstAddr, resolveErr := net.ResolveUDPAddr("udp", net.JoinHostPort(dest, strconv.Itoa(port)))
			if resolveErr != nil {
				log.Printf("[UDP] resolve %s:%d: %v", dest, port, resolveErr)
				continue
			}

			sessionKey := dstAddr.String()
			mu.Lock()
			sess, exists := sessions[sessionKey]
			if !exists {
				upstream, listenErr := net.ListenPacket("udp", ":0")
				if listenErr != nil {
					mu.Unlock()
					log.Printf("[UDP] create upstream for %s: %v", sessionKey, listenErr)
					continue
				}
				sess = &udpSession{upstream: upstream, lastSeen: time.Now()}
				sessions[sessionKey] = sess
				// Start a goroutine to relay responses from upstream back to client.
				go s.relayUDPResponses(upstream, bindLn, srcAddr)
			} else {
				sess.lastSeen = time.Now()
			}
			mu.Unlock()

			if _, writeErr := sess.upstream.WriteTo(payload, dstAddr); writeErr != nil {
				log.Printf("[UDP] write to %s: %v", sessionKey, writeErr)
			}

			if s.udpRelay.audit != nil {
				if logErr := s.udpRelay.audit.Log(audit.Event{
					Destination: dest,
					Port:        port,
					Protocol:    "udp",
					Verdict:     "allow",
				}); logErr != nil {
					log.Printf("audit log write error: %v", logErr)
				}
			}
		}
	}()

	// Block on the TCP control connection. When it closes, closeBind
	// causes the dispatch goroutine's ReadFrom to return an error,
	// exiting the loop and running its deferred cleanup.
	tcpBuf := make([]byte, 1)
	for {
		if _, err := request.Reader.Read(tcpBuf); err != nil {
			closeBind()
			return nil
		}
	}
}

// relayUDPResponses reads response datagrams from an upstream connection and
// wraps them in SOCKS5 UDP headers before sending to the client.
func (s *Server) relayUDPResponses(upstream net.PacketConn, relay *net.UDPConn, clientAddr net.Addr) {
	buf := make([]byte, 65535)
	for {
		upstream.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, srcAddr, err := upstream.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		udpAddr, ok := srcAddr.(*net.UDPAddr)
		if !ok {
			continue
		}
		resp := BuildSOCKS5UDPResponse(udpAddr.IP, udpAddr.Port, buf[:n])
		if _, writeErr := relay.WriteTo(resp, clientAddr); writeErr != nil {
			log.Printf("[UDP] write response to client: %v", writeErr)
		}
	}
}

// relayQUICResponses reads response datagrams from a QUIC proxy upstream and
// wraps them in SOCKS5 UDP headers using the original destination address
// (not the local QUIC proxy address) before sending to the client.
func (s *Server) relayQUICResponses(upstream net.PacketConn, relay *net.UDPConn, clientAddr net.Addr, originalDst *net.UDPAddr) {
	buf := make([]byte, 65535)
	for {
		upstream.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, _, err := upstream.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		resp := BuildSOCKS5UDPResponse(originalDst.IP, originalDst.Port, buf[:n])
		if _, writeErr := relay.WriteTo(resp, clientAddr); writeErr != nil {
			log.Printf("[QUIC] write response to client: %v", writeErr)
		}
	}
}

// isHTTPSPort returns true for ports commonly used by HTTPS/HTTP3.
func isHTTPSPort(port int) bool {
	return port == 443 || port == 8443
}

// generatePinID returns a random hex string used to key per-connection
// pinned IPs in the injector. Each SOCKS5 connection gets its own pin ID
// so concurrent connections to the same host do not interfere.
func generatePinID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// pinnedConn wraps a net.Conn and removes the associated pin entry from the
// injector's sync.Map when the connection is closed. This prevents pin entries
// from leaking when clients disconnect without making any outbound requests
// and ensures the pins persist for the full tunnel lifetime (not just the
// first transport dial).
type pinnedConn struct {
	net.Conn
	injector *Injector
	pinID    string
	once     sync.Once
}

func (c *pinnedConn) Close() error {
	c.once.Do(func() { c.injector.UnpinIPs(c.pinID) })
	return c.Conn.Close()
}

// bufferedConn wraps a net.Conn with a buffered reader to drain bytes read
// ahead during HTTP response parsing before reading from the raw connection.
type bufferedConn struct {
	io.Reader
	net.Conn
}

func (c *bufferedConn) Read(b []byte) (int, error) {
	return c.Reader.Read(b)
}

// dialWithHandler creates a TCP loopback pair and starts the given handler
// in a goroutine with one end of the pair. Returns the other end for
// go-socks5 to relay agent data through. Uses a real TCP pair rather than
// net.Pipe() because SSH requires kernel buffering during the version
// exchange where both sides write simultaneously.
//
// The handler must send nil on the ready channel once setup completes
// successfully, or an error if setup fails. dialWithHandler blocks until
// the ready signal arrives. If setup fails, the connection is closed and
// the error is returned to go-socks5, which reports a proper SOCKS failure
// to the client instead of a silent EOF after a successful CONNECT.
func dialWithHandler(handler func(net.Conn, chan<- error)) (net.Conn, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("handler listener: %w", err)
	}

	type acceptResult struct {
		conn net.Conn
		err  error
	}
	ch := make(chan acceptResult, 1)
	go func() {
		defer func() { _ = ln.Close() }()
		c, aErr := ln.Accept()
		ch <- acceptResult{c, aErr}
	}()

	socksEnd, dErr := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if dErr != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("dial handler: %w", dErr)
	}

	result := <-ch
	if result.err != nil {
		_ = socksEnd.Close()
		return nil, fmt.Errorf("accept handler: %w", result.err)
	}

	ready := make(chan error, 1)
	go handler(result.conn, ready)

	if setupErr := <-ready; setupErr != nil {
		_ = socksEnd.Close()
		return nil, fmt.Errorf("handler setup: %w", setupErr)
	}
	return socksEnd, nil
}

// SetBroker sets the approval broker after construction. This is needed when
// the proxy is created before the broker (e.g. to share the engine pointer
// with the TelegramChannel that is passed to the broker).
func (s *Server) SetBroker(b *channel.Broker) {
	s.rules.broker = b
	s.dnsResolver.broker = b
}

// StoreEngine atomically stores a new policy engine without acquiring the
// reload mutex. The caller must hold ReloadMu() when concurrent mutations
// are possible. Use this instead of ReloadPolicy when the caller already
// holds the mutex (e.g., the SIGHUP handler wrapping the entire reload
// sequence in a single critical section).
func (s *Server) StoreEngine(eng *policy.Engine) {
	s.rules.engine.Store(eng)
}

// StoreResolver atomically stores a new binding resolver. The caller must
// hold ReloadMu() when concurrent mutations are possible. The injector
// shares the same atomic pointer so both the dial function and MITM proxy
// see the updated bindings.
func (s *Server) StoreResolver(r *vault.BindingResolver) {
	s.resolver.Store(r)
}

// EnginePtr returns the shared atomic engine pointer. The Telegram command
// handler uses this to read and mutate the same engine as the proxy, avoiding
// split-brain windows during SIGHUP reloads.
func (s *Server) EnginePtr() *atomic.Pointer[policy.Engine] {
	return s.rules.engine
}

// ResolverPtr returns the shared atomic binding resolver pointer. The Telegram
// command handler uses this to update bindings after credential mutations,
// keeping the proxy's live binding snapshot in sync with the store.
func (s *Server) ResolverPtr() *atomic.Pointer[vault.BindingResolver] {
	return &s.resolver
}

// ReloadMu returns the shared reload mutex. The Telegram command handler
// holds this mutex when mutating the engine, ensuring mutations are
// serialized with SIGHUP-triggered engine swaps.
func (s *Server) ReloadMu() *sync.Mutex {
	return s.rules.reloadMu
}

// Addr returns the address the server is listening on.
func (s *Server) Addr() string {
	return s.listener.Addr().String()
}

// ListenAndServe starts accepting SOCKS5 connections. Accepted connections
// are tracked so GracefulShutdown can wait for them to complete.
func (s *Server) ListenAndServe() error {
	s.serving.Store(true)
	tracked := &trackedListener{Listener: s.listener, wg: &s.activeConns}
	return s.socks.Serve(tracked)
}

// IsListening returns true if the server is actively serving connections.
func (s *Server) IsListening() bool {
	return s.serving.Load() && !s.closed.Load()
}

// Close stops the server by closing the listener and any internal resources.
func (s *Server) Close() error {
	s.closed.Store(true)
	if s.injectorLn != nil {
		_ = s.injectorLn.Close()
	}
	if s.quicProxy != nil {
		_ = s.quicProxy.Close()
	}
	return s.listener.Close()
}

// GracefulShutdown stops accepting new connections, waits for in-flight
// connections to complete up to the given timeout, then closes all
// remaining resources. Returns nil if all connections drained within
// the timeout, or an error if the timeout was exceeded.
func (s *Server) GracefulShutdown(timeout time.Duration) error {
	s.closed.Store(true)
	// Stop accepting new connections.
	_ = s.listener.Close()
	if s.injectorLn != nil {
		_ = s.injectorLn.Close()
	}
	if s.quicProxy != nil {
		_ = s.quicProxy.Close()
	}

	// Wait for in-flight connections to complete, bounded by timeout.
	done := make(chan struct{})
	go func() {
		s.activeConns.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("graceful shutdown timed out after %v", timeout)
	}
}

// trackedListener wraps a net.Listener and increments/decrements a WaitGroup
// for each accepted connection. This allows GracefulShutdown to wait for
// all in-flight connections to complete.
type trackedListener struct {
	net.Listener
	wg *sync.WaitGroup
}

func (l *trackedListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.wg.Add(1)
	return &trackedConn{Conn: conn, wg: l.wg}, nil
}

// trackedConn wraps a net.Conn and decrements the WaitGroup when closed.
type trackedConn struct {
	net.Conn
	wg   *sync.WaitGroup
	once sync.Once
}

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.wg.Done() })
	return err
}
