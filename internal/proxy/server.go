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

	"github.com/armon/go-socks5"

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
	ListenAddr string
	Policy     *policy.Engine
	Audit      *audit.FileLogger
	Broker     *channel.Broker
	Provider   vault.Provider           // nil = no credential injection
	Resolver   *vault.BindingResolver   // nil = no credential injection
	VaultDir   string                   // CA cert storage dir (defaults to ~/.sluice)
	Store      *store.Store             // nil = in-memory only (no persistence)
}

// Server wraps a SOCKS5 server with policy enforcement and audit logging.
type Server struct {
	listener    net.Listener
	socks       *socks5.Server
	rules       *policyRuleSet
	dnsResolver *policyResolver
	injector    *Injector
	injectorLn  net.Listener
	sshJump     *SSHJumpHost
	mailProxy   *MailProxy
	resolver    atomic.Pointer[vault.BindingResolver]
	closed      atomic.Bool
	serving     atomic.Bool
	activeConns sync.WaitGroup
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
	// BIND and ASSOCIATE are not implemented. Return true so go-socks5
	// reaches its own handler and sends the correct commandNotSupported
	// reply instead of ruleFailure.
	if req.Command != socks5.ConnectCommand {
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
							if err := r.engine.Load().AddDynamicAllow(dest, port); err != nil {
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
				ln.Close()
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

	socksCfg := &socks5.Config{
		Rules:    rules,
		Resolver: dnsRes,
		Dial:     srv.dial,
	}
	socksServer, err := socks5.New(socksCfg)
	if err != nil {
		ln.Close()
		if srv.injectorLn != nil {
			srv.injectorLn.Close()
		}
		return nil, fmt.Errorf("socks5: %w", err)
	}
	srv.socks = socksServer

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

	s.injector = NewInjector(cfg.Provider, &s.resolver, caCert, authToken)
	injLn, injErr := net.Listen("tcp", "127.0.0.1:0")
	if injErr != nil {
		return fmt.Errorf("injector listener: %w", injErr)
	}
	s.injectorLn = injLn
	go http.Serve(injLn, s.injector.Proxy) //nolint:errcheck // best-effort

	// SSH jump host for credential-injected SSH connections.
	hostKey, hkErr := GenerateSSHHostKey()
	if hkErr != nil {
		injLn.Close()
		s.injectorLn = nil
		s.injector = nil
		return fmt.Errorf("generate SSH host key: %w", hkErr)
	}
	s.sshJump = NewSSHJumpHost(cfg.Provider, hostKey)

	// Mail proxy for IMAP/SMTP credential injection. Pass the CA cert
	// so implicit TLS ports (993, 465) can be handled via TLS MITM.
	s.mailProxy = NewMailProxy(cfg.Provider, &caCert)

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
		conn.Close()
		return nil, fmt.Errorf("send CONNECT: %w", wErr)
	}

	br := bufio.NewReader(conn)
	resp, rErr := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if rErr != nil {
		conn.Close()
		return nil, fmt.Errorf("read CONNECT response: %w", rErr)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("CONNECT rejected: %s", resp.Status)
	}

	// If the buffered reader consumed bytes past the HTTP response headers,
	// wrap the connection so those bytes are read first.
	if br.Buffered() > 0 {
		return &bufferedConn{Reader: br, Conn: conn}, nil
	}
	return conn, nil
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
		defer ln.Close()
		c, aErr := ln.Accept()
		ch <- acceptResult{c, aErr}
	}()

	socksEnd, dErr := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if dErr != nil {
		ln.Close()
		return nil, fmt.Errorf("dial handler: %w", dErr)
	}

	result := <-ch
	if result.err != nil {
		socksEnd.Close()
		return nil, fmt.Errorf("accept handler: %w", result.err)
	}

	ready := make(chan error, 1)
	go handler(result.conn, ready)

	if setupErr := <-ready; setupErr != nil {
		socksEnd.Close()
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
		s.injectorLn.Close()
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
	s.listener.Close()
	if s.injectorLn != nil {
		s.injectorLn.Close()
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
