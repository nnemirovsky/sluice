package proxy

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync/atomic"

	"github.com/armon/go-socks5"

	"github.com/nemirovsky/sluice/internal/audit"
	"github.com/nemirovsky/sluice/internal/policy"
)

// Config holds configuration for creating a new SOCKS5 proxy server.
type Config struct {
	ListenAddr string
	Policy     *policy.Engine
	Audit      *audit.FileLogger
}

// Server wraps a SOCKS5 server with policy enforcement and audit logging.
type Server struct {
	listener net.Listener
	socks    *socks5.Server
	rules    *policyRuleSet
}

type contextKey string

const ctxKeyProtocol contextKey = "protocol"
const ctxKeyEngine  contextKey = "engine"

// ProtocolFromContext retrieves the detected protocol from the request context.
func ProtocolFromContext(ctx context.Context) Protocol {
	if v, ok := ctx.Value(ctxKeyProtocol).(Protocol); ok {
		return v
	}
	return ProtoGeneric
}

// policyResolver performs DNS resolution only for destinations that could be
// allowed by policy. Definitely-denied destinations return nil IP (no DNS
// lookup) to prevent leaks. For potentially-allowed destinations, DNS failures
// return an error so go-socks5 sends a hostUnreachable reply instead of the
// ruleFailure that would result from failing inside Allow().
type policyResolver struct {
	engine *atomic.Pointer[policy.Engine]
	audit  *audit.FileLogger
}

func (r *policyResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	dest := strings.TrimRight(name, ".")

	eng := r.engine.Load()
	// Store engine snapshot in context so Allow() evaluates against the
	// same policy version, preventing a SIGHUP reload from splitting a
	// single request across two different policy snapshots.
	ctx = context.WithValue(ctx, ctxKeyEngine, eng)
	if !eng.CouldBeAllowed(dest) {
		// Definitely denied on all ports: skip DNS to prevent leaks.
		// Allow() will deny the connection with ruleFailure.
		return ctx, nil, nil
	}

	// Destination might be allowed: resolve DNS. Failures return an error
	// so go-socks5 sends hostUnreachable (more accurate than ruleFailure).
	ips, err := net.LookupIP(dest)
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
	if len(ips) == 0 {
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

	return ctx, ips[0], nil
}

type policyRuleSet struct {
	engine *atomic.Pointer[policy.Engine]
	audit  *audit.FileLogger
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

	// Determine the effective outcome (ask is treated as deny until Telegram is configured).
	allowed := false
	effectiveVerdict := verdict
	var reason string
	switch verdict {
	case policy.Allow:
		allowed = true
	case policy.Ask:
		effectiveVerdict = policy.Deny
		reason = "ask treated as deny (Telegram not configured)"
		log.Printf("[ASK->DENY] %s:%d (Telegram not configured)", dest, port)
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

	rules := &policyRuleSet{engine: enginePtr, audit: cfg.Audit}
	resolver := &policyResolver{engine: enginePtr, audit: cfg.Audit}

	socksCfg := &socks5.Config{
		Rules:    rules,
		Resolver: resolver,
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
func (s *Server) ReloadPolicy(eng *policy.Engine) {
	s.rules.engine.Store(eng)
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
