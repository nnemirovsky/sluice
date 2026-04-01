package proxy

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/armon/go-socks5"

	"github.com/nemirovsky/sluice/internal/audit"
	"github.com/nemirovsky/sluice/internal/policy"
	"github.com/nemirovsky/sluice/internal/telegram"
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
	Broker     *telegram.ApprovalBroker
}

// Server wraps a SOCKS5 server with policy enforcement and audit logging.
type Server struct {
	listener net.Listener
	socks    *socks5.Server
	rules    *policyRuleSet
}

type contextKey string

const ctxKeyProtocol       contextKey = "protocol"
const ctxKeyEngine         contextKey = "engine"
const ctxKeyFallbackAddrs  contextKey = "fallbackAddrs"

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
	broker *telegram.ApprovalBroker
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
	broker   *telegram.ApprovalBroker
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
				case telegram.ResponseAllowOnce:
					allowed = true
					effectiveVerdict = policy.Allow
					reason = "user approved once"
					log.Printf("[ASK->ALLOW] %s:%d (user approved once)", dest, port)
				case telegram.ResponseAlwaysAllow:
					allowed = true
					effectiveVerdict = policy.Allow
					reason = "user approved always"
					log.Printf("[ASK->ALLOW+SAVE] %s:%d (user approved always)", dest, port)
					// Hold reloadMu to prevent a concurrent SIGHUP from swapping
					// the engine between Load() and AddDynamicAllow(), which would
					// write the rule to the retired engine.
					r.reloadMu.Lock()
					if err := r.engine.Load().AddDynamicAllow(dest, port); err != nil {
						log.Printf("[WARN] failed to add dynamic allow rule for %s:%d: %v", dest, port, err)
					}
					r.reloadMu.Unlock()
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

	enginePtr := new(atomic.Pointer[policy.Engine])
	enginePtr.Store(cfg.Policy)
	reloadMu := new(sync.Mutex)

	rules := &policyRuleSet{engine: enginePtr, reloadMu: reloadMu, audit: cfg.Audit, broker: cfg.Broker}
	resolver := &policyResolver{engine: enginePtr, audit: cfg.Audit, broker: cfg.Broker}

	socksCfg := &socks5.Config{
		Rules:    rules,
		Resolver: resolver,
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
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
		},
	}
	socksServer, err := socks5.New(socksCfg)
	if err != nil {
		ln.Close()
		return nil, fmt.Errorf("socks5: %w", err)
	}

	return &Server{
		listener: ln,
		socks:    socksServer,
		rules:    rules,
	}, nil
}

// ReloadPolicy atomically swaps the policy engine used for future connections.
// Holds reloadMu to prevent racing with in-flight "Always Allow" mutations.
func (s *Server) ReloadPolicy(eng *policy.Engine) {
	s.rules.reloadMu.Lock()
	defer s.rules.reloadMu.Unlock()
	s.rules.engine.Store(eng)
}

// EnginePtr returns the shared atomic engine pointer. The Telegram command
// handler uses this to read and mutate the same engine as the proxy, avoiding
// split-brain windows during SIGHUP reloads.
func (s *Server) EnginePtr() *atomic.Pointer[policy.Engine] {
	return s.rules.engine
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

// ListenAndServe starts accepting SOCKS5 connections.
func (s *Server) ListenAndServe() error {
	return s.socks.Serve(s.listener)
}

// Close stops the server by closing the listener.
func (s *Server) Close() error {
	return s.listener.Close()
}
