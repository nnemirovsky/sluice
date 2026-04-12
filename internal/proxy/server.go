package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
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

	mitmcert "github.com/lqqyt2423/go-mitmproxy/cert"
	mitmproxy "github.com/lqqyt2423/go-mitmproxy/proxy"
	"github.com/nemirovsky/sluice/internal/audit"
	"github.com/nemirovsky/sluice/internal/channel"
	"github.com/nemirovsky/sluice/internal/policy"
	"github.com/nemirovsky/sluice/internal/store"
	"github.com/nemirovsky/sluice/internal/vault"
	"github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
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

// byteDetectTimeout is how long to wait for the client's first bytes during
// byte-level protocol detection on non-standard ports. Kept short to minimize
// latency for server-first protocols where the client never sends first.
const byteDetectTimeout = 200 * time.Millisecond

// Config holds configuration for creating a new SOCKS5 proxy server.
type Config struct {
	ListenAddr      string
	Policy          *policy.Engine
	Audit           *audit.FileLogger
	Broker          *channel.Broker
	Provider        vault.Provider         // nil = no credential injection
	Resolver        *vault.BindingResolver // nil = no credential injection
	VaultDir        string                 // CA cert storage dir (defaults to ~/.sluice)
	Store           *store.Store           // nil = in-memory only (no persistence)
	WSBlockRules    []WSBlockRuleConfig    // WebSocket content deny rules
	WSRedactRules   []WSRedactRuleConfig   // WebSocket content redact rules
	QUICBlockRules  []QUICBlockRuleConfig  // QUIC/HTTP3 content deny rules
	QUICRedactRules []QUICRedactRuleConfig // QUIC/HTTP3 content redact rules
	DNSResolver     string                 // upstream DNS resolver for intercepted queries (default: 8.8.8.8:53)
	SelfBypass      []string               // host:port addresses to auto-allow without policy evaluation (sluice's own listeners)
}

// Server wraps a SOCKS5 server with policy enforcement and audit logging.
type Server struct {
	listener       net.Listener
	socks          *socks5.Server
	rules          *policyRuleSet
	dnsResolver    *policyResolver
	mitmProxy      *mitmproxy.Proxy
	mitmAddr       string // go-mitmproxy listener address for SOCKS5 dial
	mitmAuthSecret string // shared secret for MITM proxy auth (X-Sluice-Auth header)
	addon          *SluiceAddon
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

const (
	ctxKeyProtocol         contextKey = "protocol"
	ctxKeyEngine           contextKey = "engine"
	ctxKeyFallbackAddrs    contextKey = "fallbackAddrs"
	ctxKeyFQDN             contextKey = "fqdn"
	ctxKeySNIDeferred      contextKey = "sniDeferred"      // true when policy check deferred for SNI peeking
	ctxKeyPerRequestPolicy contextKey = "perRequestPolicy" // *RequestPolicyChecker for per-HTTP-request policy checks
	ctxKeySkipPerRequest   contextKey = "skipPerRequest"   // true when connection matched an explicit allow rule
)

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

// isTLSPort returns true for ports that typically carry TLS traffic.
func isTLSPort(port int) bool {
	switch port {
	case 443, 8443, 993, 995, 465:
		return true
	default:
		return false
	}
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
	engine         *atomic.Pointer[policy.Engine]
	reloadMu       *sync.Mutex // serializes engine swaps and dynamic rule mutations
	audit          *audit.FileLogger
	broker         *channel.Broker
	store          *store.Store
	selfBypass     map[string]bool // host:port addresses that bypass policy (sluice's own listeners)
	dnsInterceptor *DNSInterceptor // reverse DNS cache for IP -> hostname recovery
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
	ipOnly := false // true when SOCKS5 CONNECT had no FQDN
	if dest == "" {
		if req.DestAddr.IP != nil {
			ipStr := req.DestAddr.IP.String()
			port := req.DestAddr.Port

			// For TLS ports, always defer to SNI extraction (happy path).
			// SNI from the TLS ClientHello is more reliable than the DNS
			// reverse cache because it comes directly from the client and
			// doesn't expire. DNS cache is used only for non-TLS protocols.
			if isTLSPort(port) {
				dest = ipStr
				ipOnly = true
			} else if r.dnsInterceptor != nil {
				if hostname := r.dnsInterceptor.ReverseLookup(ipStr); hostname != "" {
					dest = hostname
				} else {
					dest = ipStr
					ipOnly = true
				}
			} else {
				dest = ipStr
				ipOnly = true
			}
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

	// Self-bypass: auto-allow connections to sluice's own listener
	// addresses (health/MCP server) without policy evaluation. This
	// prevents the agent's MCP HTTP connection from being blocked or
	// triggering approval when routed through the SOCKS5 proxy.
	if len(r.selfBypass) > 0 {
		target := net.JoinHostPort(dest, strconv.Itoa(port))
		if r.selfBypass[target] {
			log.Printf("[BYPASS] %s (self)", target)
			proto := DetectProtocol(port)
			ctx = context.WithValue(ctx, ctxKeyProtocol, proto)
			ctx = context.WithValue(ctx, ctxKeyFQDN, dest)
			return ctx, true
		}
	}

	// Use the engine snapshot from Resolve() (stored in context) to ensure
	// consistent policy evaluation within a single request. For IP-based
	// requests where Resolve() was not called, load fresh from the pointer.
	eng, _ := ctx.Value(ctxKeyEngine).(*policy.Engine)
	if eng == nil {
		eng = r.engine.Load()
	}
	verdict, matchSource := eng.EvaluateDetailed(dest, port)

	// SNI deferral: when the destination is an IP with no DNS reverse cache
	// hit and the port is typically TLS, defer the policy check to the custom
	// connect handler which will peek the TLS ClientHello for SNI. This lets
	// hostname-based allow rules match even when tun2proxy sends raw IPs.
	if ipOnly && verdict != policy.Allow && verdict != policy.Deny && isTLSPort(port) {
		log.Printf("[SNI-DEFER] %s:%d (deferring policy for SNI peek)", dest, port)
		proto := DetectProtocol(port)
		ctx = context.WithValue(ctx, ctxKeyProtocol, proto)
		ctx = context.WithValue(ctx, ctxKeyFQDN, dest)
		ctx = context.WithValue(ctx, ctxKeySNIDeferred, true)
		ctx = context.WithValue(ctx, ctxKeyEngine, eng)
		return ctx, true
	}

	// Determine the effective outcome.
	allowed := false
	effectiveVerdict := verdict
	var reason string
	// alwaysAllowPersisted is set to true only when an ask->ResponseAlwaysAllow
	// both wrote the rule to the store AND swapped a recompiled engine in
	// successfully. This gates the ctxKeySkipPerRequest flag below so a
	// partial persistence failure does not silently allow all subsequent
	// requests without re-triggering per-request policy.
	var alwaysAllowPersisted bool
	switch verdict {
	case policy.Allow:
		allowed = true
	case policy.Ask:
		if r.broker == nil {
			effectiveVerdict = policy.Deny
			reason = "ask treated as deny (no approval broker)"
			log.Printf("[ASK->DENY] %s:%d (no approval broker)", dest, port)
		} else {
			// Auto-allow the SOCKS5 CONNECT without prompting the user.
			// Approval happens per-request inside the MITM handler where
			// the HTTP method and path are known, producing a single
			// combined Telegram message per request instead of two
			// separate messages (connection + request).
			allowed = true
			effectiveVerdict = policy.Allow
			reason = "ask deferred to per-request"
			log.Printf("[ASK->DEFER] %s:%d (approval deferred to per-request)", dest, port)
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

	// Single audit entry reflecting the final outcome. Protocol is set
	// so audit grep is consistent with per-request audit entries which
	// also populate this field.
	if r.audit != nil {
		if err := r.audit.Log(audit.Event{
			Destination: dest,
			Port:        port,
			Protocol:    DetectProtocol(port).String(),
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

		// Per-request policy wiring. Skip per-request checks entirely when
		// any of the following hold:
		//   1. The connect-time verdict matched an explicit allow rule
		//      (RuleMatch). Subsequent requests will keep matching the same
		//      rule so paying the per-request cost is pure waste.
		//   2. The ask flow resolved to ResponseAlwaysAllow and the rule was
		//      successfully persisted (both store write and engine swap).
		//      At that point the new rule is live in the engine and
		//      functions exactly like case 1. A partial persistence failure
		//      falls through to the checker path as a safety net.
		//   3. There is no broker wired up. Without a broker, the checker
		//      can only deny (ask -> deny) or allow (rule/default allow),
		//      but since we already allowed this connection the only thing
		//      the checker could do differently is start denying mid-stream
		//      if the engine is reloaded. Skip it to avoid the overhead.
		//
		// Otherwise attach a checker so the HTTP MITM handler re-evaluates
		// policy on every request. This is how "Allow Once" becomes
		// per-request instead of per-connection. When the connection-level
		// ask resolved to ResponseAllowOnce, the checker is seeded with one
		// prepaid allow credit so the first HTTP request flows through
		// without re-prompting the user (the CONNECT approval is reused for
		// the first request on the new tunnel).
		skipPerRequest := (verdict == policy.Allow && matchSource == policy.RuleMatch) ||
			alwaysAllowPersisted ||
			r.broker == nil
		if skipPerRequest {
			ctx = context.WithValue(ctx, ctxKeySkipPerRequest, true)
		} else {
			// No seed credit: every HTTP request triggers its own
			// per-request approval with method and path visible in
			// the Telegram message.
			checker := NewRequestPolicyChecker(r.engine, r.broker,
				WithPersist(r.buildPersistFunc()),
			)
			ctx = context.WithValue(ctx, ctxKeyPerRequestPolicy, checker)
		}
	}
	return ctx, allowed
}

// persistApprovalRule writes an allow/deny rule for dest:port coming from an
// ask->Always* approval and atomically swaps in a recompiled engine. Returns
// true only when both the store write and engine swap succeed. A false return
// means the in-memory engine may still evaluate dest:port as ask, so callers
// should attach a per-request checker as a safety net.
//
// Callers:
//   - persistAlwaysAllow / persistAlwaysDeny: connection-level approvals.
//   - buildPersistFunc closure: per-request approvals via RequestPolicyChecker.
//   - sniSaveRule: SNI-peek approvals in the custom connect handler.
//
// verdict must be "allow" or "deny".
func (r *policyRuleSet) persistApprovalRule(verdict, dest string, port int) bool {
	// Hold reloadMu to prevent a concurrent SIGHUP from swapping the
	// engine between the store write and recompile.
	r.reloadMu.Lock()
	defer r.reloadMu.Unlock()
	if r.store == nil {
		log.Printf("[WARN] always-%s for %s:%d not persisted (no store)", verdict, dest, port)
		return false
	}
	if _, storeErr := r.store.AddRule(verdict, store.RuleOpts{Destination: dest, Ports: []int{port}, Source: "approval"}); storeErr != nil {
		log.Printf("[WARN] failed to persist %s rule for %s:%d: %v", verdict, dest, port, storeErr)
		return false
	}
	newEng, recompErr := policy.LoadFromStore(r.store)
	if recompErr != nil {
		log.Printf("[WARN] failed to recompile engine after always-%s: %v", verdict, recompErr)
		return false
	}
	if valErr := newEng.Validate(); valErr != nil {
		log.Printf("[WARN] engine validation failed after always-%s: %v", verdict, valErr)
		return false
	}
	r.engine.Store(newEng)
	return true
}

// buildPersistFunc returns a closure that persists a new allow/deny rule
// via the SOCKS5 rule set's store and swaps in a recompiled engine. It
// mirrors the always-allow/always-deny handling in Allow() so per-request
// approvals land in the same store/engine state as connection-level ones.
// Returns nil when the rule set has no store wired up (tests, standalone),
// in which case the checker logs a warning instead of persisting.
func (r *policyRuleSet) buildPersistFunc() PersistRuleFunc {
	if r.store == nil {
		return nil
	}
	return func(v PersistVerdict, dest string, port int) {
		verdictStr := "allow"
		label := "[REQ-APPROVAL-SAVE:allow]"
		if v == PersistDeny {
			verdictStr = "deny"
			label = "[REQ-APPROVAL-SAVE:deny]"
		}
		if ok := r.persistApprovalRule(verdictStr, dest, port); !ok {
			log.Printf("%s %s:%d persistence failed", label, dest, port)
			return
		}
		log.Printf("%s %s:%d persisted", label, dest, port)
	}
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

	var bypassSet map[string]bool
	if len(cfg.SelfBypass) > 0 {
		bypassSet = make(map[string]bool, len(cfg.SelfBypass))
		for _, addr := range cfg.SelfBypass {
			bypassSet[addr] = true
		}
	}

	// Create UDP relay and DNS interceptor for UDP ASSOCIATE sessions.
	srv.udpRelay = NewUDPRelay(enginePtr, cfg.Audit)
	srv.dnsInterceptor = NewDNSInterceptor(enginePtr, cfg.Audit, cfg.DNSResolver)

	rules := &policyRuleSet{engine: enginePtr, reloadMu: reloadMu, audit: cfg.Audit, broker: cfg.Broker, store: cfg.Store, selfBypass: bypassSet, dnsInterceptor: srv.dnsInterceptor}
	dnsRes := &policyResolver{engine: enginePtr, audit: cfg.Audit, broker: cfg.Broker}
	srv.rules = rules
	srv.dnsResolver = dnsRes

	srv.socks = socks5.NewServer(
		socks5.WithRule(rules),
		socks5.WithResolver(dnsRes),
		socks5.WithDial(srv.dial),
		socks5.WithConnectHandle(srv.handleConnect),
		socks5.WithAssociateHandle(srv.handleAssociate),
	)

	return srv, nil
}

// setupInjection initializes the credential injection infrastructure (HTTPS
// MITM via go-mitmproxy, SSH jump host, mail proxy). Returns an error if
// any component fails. The caller decides whether the error is fatal based
// on whether bindings exist.
func (s *Server) setupInjection(cfg Config, _ net.Listener) error {
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

	// Create the SluiceAddon for go-mitmproxy.
	addonOpts := []SluiceAddonOption{
		WithResolver(&s.resolver),
		WithProvider(cfg.Provider),
		WithWSProxy(wsProxy),
	}
	if cfg.Audit != nil {
		addonOpts = append(addonOpts, WithAuditLogger(cfg.Audit))
	}
	s.addon = NewSluiceAddon(addonOpts...)

	// Populate the OAuth token URL index from credential metadata so
	// the response handler can detect OAuth token endpoints from startup.
	if cfg.Store != nil {
		if metas, metaErr := cfg.Store.ListCredentialMeta(); metaErr == nil {
			s.addon.UpdateOAuthIndex(metas)
		} else {
			log.Printf("[MITM-OAUTH] failed to load credential meta for index: %v", metaErr)
		}
	}

	// Create a cert.CA adapter so go-mitmproxy uses our existing CA.
	ca, caAdaptErr := newSluiceCA(caCert)
	if caAdaptErr != nil {
		return fmt.Errorf("adapt CA for mitmproxy: %w", caAdaptErr)
	}

	// Pre-allocate a listener to discover the port, then release it so
	// go-mitmproxy's Start() can bind. There is a small TOCTOU window
	// between Close() and Start() where another process could grab the
	// port. go-mitmproxy does not expose a custom net.Listener option,
	// so this is the only way to discover the address. The risk is
	// negligible on localhost (only sluice binds ephemeral ports here).
	tmpLn, lnErr := net.Listen("tcp", "127.0.0.1:0")
	if lnErr != nil {
		return fmt.Errorf("mitmproxy listener: %w", lnErr)
	}
	mitmAddr := tmpLn.Addr().String()
	_ = tmpLn.Close()

	mp, mpErr := mitmproxy.NewProxy(&mitmproxy.Options{
		Addr: mitmAddr,
		// SslInsecure skips certificate verification on upstream connections.
		// Required because go-mitmproxy connects to the real upstream server
		// from the MITM proxy, and we need to accept whatever cert the upstream
		// presents (sluice's CA is only for the agent-facing side).
		SslInsecure: true,
		NewCaFunc:   func() (mitmcert.CA, error) { return ca, nil },
	})
	if mpErr != nil {
		return fmt.Errorf("create mitmproxy: %w", mpErr)
	}

	// Always intercept HTTPS connections so phantom tokens can be
	// replaced in any traffic (MITM-all policy).
	mp.SetShouldInterceptRule(func(_ *http.Request) bool { return true })

	// Authenticate CONNECT requests with a shared secret so only sluice's
	// own SOCKS5 dial path can use the MITM listener. Without this, any
	// process on localhost could connect directly and bypass policy checks.
	// In Docker deployments the listener is network-isolated, but --runtime
	// none exposes it on the host.
	var secretBytes [16]byte
	if _, randErr := rand.Read(secretBytes[:]); randErr != nil {
		return fmt.Errorf("generate mitm auth secret: %w", randErr)
	}
	mitmSecret := hex.EncodeToString(secretBytes[:])
	mp.SetAuthProxy(func(_ http.ResponseWriter, req *http.Request) (bool, error) {
		return req.Header.Get("X-Sluice-Auth") == mitmSecret, nil
	})

	mp.AddAddon(s.addon)
	s.mitmProxy = mp
	s.mitmAddr = mitmAddr
	s.mitmAuthSecret = mitmSecret

	go func() {
		if startErr := mp.Start(); startErr != nil {
			log.Printf("[MITM] proxy stopped: %v", startErr)
		}
	}()

	// SSH jump host for credential-injected SSH connections.
	hostKey, hkErr := GenerateSSHHostKey()
	if hkErr != nil {
		_ = mp.Close()
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

// bindingIsMetaOnly returns true when all protocols in the binding are
// meta-protocols (tcp/udp). A meta-protocol binding matches a family of
// specific protocols rather than identifying one, so the ResolveProtocolHint
// fast path should still be attempted to find a more specific binding.
func bindingIsMetaOnly(b vault.Binding) bool {
	if len(b.Protocols) == 0 {
		return false
	}
	for _, p := range b.Protocols {
		if !vault.IsMetaProtocol(p) {
			return false
		}
	}
	return true
}

// skipPerRequestFromContext returns true when the SOCKS5 context flags
// the connection as exempt from per-request policy checks.
func skipPerRequestFromContext(ctx context.Context) bool {
	skip, _ := ctx.Value(ctxKeySkipPerRequest).(bool)
	return skip
}

// perRequestCheckerFromContext extracts the per-request policy checker from
// the SOCKS5 context. Returns nil when the connection matched an explicit
// allow rule (ctxKeySkipPerRequest is set) or when no checker is attached.
func perRequestCheckerFromContext(ctx context.Context) *RequestPolicyChecker {
	if skipPerRequestFromContext(ctx) {
		return nil
	}
	if c, ok := ctx.Value(ctxKeyPerRequestPolicy).(*RequestPolicyChecker); ok {
		return c
	}
	return nil
}

// storePendingChecker transfers the per-request policy state from the
// SOCKS5 context into the SluiceAddon's pending checkers map so that
// ServerConnected can attach it to the connection state. The dest
// argument is "host:port" matching the CONNECT target.
func (s *Server) storePendingChecker(ctx context.Context, dest string) {
	if s.addon == nil {
		return
	}
	skip := skipPerRequestFromContext(ctx)
	checker := perRequestCheckerFromContext(ctx)
	if skip || checker != nil {
		s.addon.PendingChecker(dest, checker, skip)
	}
}

// cancelPendingChecker removes the most recent pending checker for dest
// when dialThroughMITM fails after storePendingChecker was called.
// Without this cleanup a stale checker would leak and attach to the next
// connection to the same host:port.
func (s *Server) cancelPendingChecker(dest string) {
	if s.addon == nil {
		return
	}
	s.addon.CancelPendingChecker(dest)
}

// dialThroughMITM connects to the local go-mitmproxy listener and
// establishes an HTTP CONNECT tunnel for the target host. go-mitmproxy
// intercepts the CONNECT request and sets up MITM for the inner
// HTTP/HTTPS traffic. The per-request checker is passed through the
// addon's pendingCheckers map (keyed by host:port) before calling this.
// The authSecret is sent as X-Sluice-Auth to pass go-mitmproxy's
// SetAuthProxy check.
func dialThroughMITM(mitmAddr, host string, port int, authSecret string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", mitmAddr, connectTimeout)
	if err != nil {
		return nil, fmt.Errorf("connect to mitmproxy: %w", err)
	}

	target := net.JoinHostPort(host, strconv.Itoa(port))
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nX-Sluice-Auth: %s\r\n\r\n", target, target, authSecret)
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

// dial is the custom dialer for go-socks5. When a credential binding matches
// the destination, the connection is routed through the appropriate injection
// handler (HTTPS MITM via go-mitmproxy, SSH jump host, or mail proxy).
// Otherwise it falls through to a direct TCP connection with DNS fallback
// support.
func (s *Server) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	perReqChecker := perRequestCheckerFromContext(ctx)
	if r := s.resolver.Load(); r != nil {
		fqdn, _ := ctx.Value(ctxKeyFQDN).(string)
		if fqdn != "" {
			_, portStr, _ := net.SplitHostPort(addr)
			port, _ := strconv.Atoi(portStr)

			proto := ProtocolFromContext(ctx)
			// Use protocol-aware resolution so the correct binding is
			// selected when multiple bindings exist for the same host:port
			// with different protocols (e.g. one for SSH, one for HTTPS).
			binding, ok := r.ResolveForProtocol(fqdn, port, proto.String())
			if !ok {
				binding, ok = r.Resolve(fqdn, port)
				if ok && len(binding.Protocols) == 1 {
					if hint, hok := r.ResolveProtocolHint(fqdn, port); hok {
						if parsed, perr := ParseProtocol(hint); perr == nil {
							proto = parsed
						}
					}
				}
			}
			if ok && proto == ProtoGeneric && (len(binding.Protocols) == 0 || bindingIsMetaOnly(binding)) {
				if hint, hok := r.ResolveProtocolHint(fqdn, port); hok {
					if parsed, perr := ParseProtocol(hint); perr == nil {
						proto = parsed
					}
					if specific, sok := r.ResolveForProtocol(fqdn, port, hint); sok {
						binding = specific
					}
				}
			}
			if ok {
				hostAddr := net.JoinHostPort(fqdn, portStr)
				dialAddrs := []string{addr}
				if fallbacks, ok := ctx.Value(ctxKeyFallbackAddrs).([]net.IP); ok {
					for _, ip := range fallbacks {
						dialAddrs = append(dialAddrs, net.JoinHostPort(ip.String(), portStr))
					}
				}

				switch proto {
				case ProtoHTTPS:
					if s.mitmProxy != nil {
						dest := net.JoinHostPort(fqdn, strconv.Itoa(port))
						s.storePendingChecker(ctx, dest)
						conn, err := dialThroughMITM(s.mitmAddr, fqdn, port, s.mitmAuthSecret)
						if err != nil {
							s.cancelPendingChecker(dest)
							return nil, err
						}
						return conn, nil
					}
				case ProtoHTTP:
					// Plain HTTP: go-mitmproxy only parses TLS-intercepted traffic.
					// Fall through to direct connection. Phantom replacement for
					// plain HTTP bindings is not yet supported via go-mitmproxy.
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
				// Non-standard port with binding: use byte-level detection
				// to determine the correct injection handler.
				if proto == ProtoGeneric || proto == ProtoTCP {
					bnd := binding
					return dialWithHandler(func(agentConn net.Conn, ready chan<- error) {
						s.handleWithDetection(agentConn, ready, &bnd, fqdn, port, hostAddr, dialAddrs, perReqChecker)
					})
				}
			}
		}
	}

	// Route unbound HTTP/HTTPS through go-mitmproxy when available so
	// phantom tokens are stripped from requests to hosts without bindings.
	if s.mitmProxy != nil {
		_, portStr, _ := net.SplitHostPort(addr)
		port, _ := strconv.Atoi(portStr)
		proto := DetectProtocol(port)
		switch proto {
		case ProtoHTTPS:
			fqdn, _ := ctx.Value(ctxKeyFQDN).(string)
			if fqdn == "" {
				host, _, _ := net.SplitHostPort(addr)
				fqdn = host
			}
			dest := net.JoinHostPort(fqdn, strconv.Itoa(port))
			s.storePendingChecker(ctx, dest)
			conn, err := dialThroughMITM(s.mitmAddr, fqdn, port, s.mitmAuthSecret)
			if err != nil {
				s.cancelPendingChecker(dest)
				// Fall through to direct connection below.
				log.Printf("[MITM] dial through mitmproxy failed for %s: %v", dest, err)
			} else {
				return conn, nil
			}
		case ProtoGeneric:
			// Non-standard port without binding: use byte-level
			// detection to catch HTTPS/HTTP for phantom stripping.
			fqdn, _ := ctx.Value(ctxKeyFQDN).(string)
			if fqdn == "" {
				host, _, _ := net.SplitHostPort(addr)
				fqdn = host
			}
			unboundAddrs := []string{addr}
			if fallbacks, ok := ctx.Value(ctxKeyFallbackAddrs).([]net.IP); ok {
				for _, ip := range fallbacks {
					unboundAddrs = append(unboundAddrs, net.JoinHostPort(ip.String(), portStr))
				}
			}
			hostAddr := net.JoinHostPort(fqdn, portStr)
			return dialWithHandler(func(agentConn net.Conn, ready chan<- error) {
				s.handleWithDetection(agentConn, ready, nil, fqdn, port, hostAddr, unboundAddrs, perReqChecker)
			})
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

// handleWithDetection peeks the agent's first bytes to detect the protocol
// and routes through the appropriate injection handler. Used for connections
// on non-standard ports where port-based detection returned ProtoGeneric.
// The binding parameter is nil for unbound connections (phantom stripping only).
// The checker parameter is the per-request policy checker carried from the
// SOCKS5 context, used by the HTTP MITM path to enforce per-request policy.
// It is nil when the connection matched an explicit allow rule.
func (s *Server) handleWithDetection(
	agentConn net.Conn,
	ready chan<- error,
	binding *vault.Binding,
	fqdn string,
	port int,
	hostAddr string,
	dialAddrs []string,
	checker *RequestPolicyChecker,
) {
	defer func() { _ = agentConn.Close() }()
	// Signal ready immediately: byte detection requires reading client
	// data, which only arrives after the SOCKS5 CONNECT succeeds. Any
	// handler failures after this point close the connection, surfacing
	// as an application-layer error rather than a SOCKS5 failure.
	ready <- nil

	// Read first bytes with a deadline. For client-first protocols (TLS,
	// SSH, HTTP), data arrives quickly. For server-first or idle
	// connections, the deadline fires and we fall through to direct relay.
	peekBuf := make([]byte, 4)
	_ = agentConn.SetReadDeadline(time.Now().Add(byteDetectTimeout))
	n, _ := io.ReadFull(agentConn, peekBuf)
	_ = agentConn.SetReadDeadline(time.Time{})

	proto := DetectFromClientBytes(peekBuf[:n])

	// Replay peeked bytes before the rest of the stream.
	var peekReader io.Reader = agentConn
	if n > 0 {
		peekReader = io.MultiReader(bytes.NewReader(peekBuf[:n]), agentConn)
	}
	peekConn := &bufferedConn{Reader: peekReader, Conn: agentConn}

	if proto != ProtoGeneric {
		log.Printf("[DETECT] %s byte detection -> %s", hostAddr, proto)
	}

	// Re-resolve binding with detected protocol: the initial resolution in
	// dial() used "generic" (non-standard port), so a meta-protocol binding
	// (e.g. protocols=["tcp"]) may have been selected over a more specific
	// one (e.g. protocols=["ssh"]). Now that byte detection revealed the
	// actual protocol, re-resolve to pick the most specific binding.
	if proto != ProtoGeneric && binding != nil {
		if r := s.resolver.Load(); r != nil {
			if specific, ok := r.ResolveForProtocol(fqdn, port, proto.String()); ok {
				binding = &specific
			}
		}
	}

	switch proto {
	case ProtoHTTPS:
		if s.mitmProxy != nil {
			dest := net.JoinHostPort(fqdn, strconv.Itoa(port))
			s.addon.PendingChecker(dest, checker, checker == nil)
			mitmConn, err := dialThroughMITM(s.mitmAddr, fqdn, port, s.mitmAuthSecret)
			if err != nil {
				s.addon.CancelPendingChecker(dest)
				log.Printf("[DETECT] mitmproxy failed for %s: %v", hostAddr, err)
				if binding != nil {
					return
				}
				relayDirect(peekConn, dialAddrs)
				return
			}
			bidirectionalRelay(peekConn, mitmConn)
			return
		}
	case ProtoHTTP:
		// Plain HTTP detected by byte sniffing. go-mitmproxy only parses
		// TLS-intercepted traffic through CONNECT tunnels, so plain HTTP
		// goes through direct relay without phantom replacement.
		//
		// Known gap: credentials bound to plain HTTP on non-standard ports
		// will not be injected and phantom tokens will not be stripped.
		// This is acceptable because (1) credential bindings almost always
		// target HTTPS endpoints, and (2) the old goproxy-based path had
		// the same limitation. A future fix could add a lightweight HTTP
		// reverse proxy here or route plain HTTP through go-mitmproxy's
		// non-TLS code path if it gains support.
		relayDirect(peekConn, dialAddrs)
		return
	case ProtoSSH:
		if s.sshJump != nil && binding != nil {
			// Pass nil for ready: SOCKS5 CONNECT already succeeded (see
			// comment above), so the handler's readiness signal is unused.
			// Both HandleConnection implementations guard with
			// "if ready != nil" before sending.
			if err := s.sshJump.HandleConnection(peekConn, dialAddrs, hostAddr, *binding, nil); err != nil {
				log.Printf("[SSH] handler error for %s: %v", hostAddr, err)
			}
			return
		}
	case ProtoIMAP, ProtoSMTP:
		if s.mailProxy != nil && binding != nil {
			if err := s.mailProxy.HandleConnection(peekConn, dialAddrs, hostAddr, *binding, proto, nil); err != nil {
				log.Printf("[MAIL] handler error for %s: %v", hostAddr, err)
			}
			return
		}
	}

	// Server-first detection: when no client bytes arrived (timeout),
	// the remote might be a server-first protocol (SMTP, IMAP). Connect
	// upstream and peek the server's first bytes to find out. Only attempt
	// this when a binding and mail proxy exist, since server-first detection
	// can only route through the mail proxy and the upstream probe is wasted
	// without a binding to inject.
	if n == 0 && binding != nil && s.mailProxy != nil {
		s.handleServerFirstDetection(peekConn, binding, hostAddr, dialAddrs)
		return
	}

	relayDirect(peekConn, dialAddrs)
}

// serverDetectTimeout bounds how long to wait for the server's first bytes
// during server-first protocol detection (SMTP banner, IMAP greeting).
const serverDetectTimeout = 500 * time.Millisecond

// handleServerFirstDetection connects upstream and peeks the server's first
// bytes to detect server-first protocols (SMTP, IMAP). If a match is found
// and a binding exists, the connection is routed through the mail proxy.
// Otherwise, the server's pre-read bytes are relayed and the connection
// continues as a direct relay.
func (s *Server) handleServerFirstDetection(
	agentConn net.Conn,
	binding *vault.Binding,
	hostAddr string,
	dialAddrs []string,
) {
	d := &net.Dialer{Timeout: connectTimeout}
	var upstream net.Conn
	var err error
	for _, addr := range dialAddrs {
		upstream, err = d.Dial("tcp", addr)
		if err == nil {
			break
		}
	}
	if err != nil {
		log.Printf("[DETECT] server-first upstream dial failed for %s: %v", hostAddr, err)
		return
	}

	// Peek server's first bytes with a short deadline.
	serverBuf := make([]byte, 8)
	_ = upstream.SetReadDeadline(time.Now().Add(serverDetectTimeout))
	sn, _ := io.ReadFull(upstream, serverBuf)
	_ = upstream.SetReadDeadline(time.Time{})

	serverProto := DetectFromServerBytes(serverBuf[:sn])

	if serverProto != ProtoGeneric {
		log.Printf("[DETECT] %s server byte detection -> %s", hostAddr, serverProto)
	}

	// Re-resolve binding with detected server protocol (same rationale as
	// the client-byte re-resolution in handleWithDetection).
	if serverProto != ProtoGeneric && binding != nil {
		if r := s.resolver.Load(); r != nil {
			if host, portStr, err := net.SplitHostPort(hostAddr); err == nil {
				if p, err := strconv.Atoi(portStr); err == nil {
					if specific, ok := r.ResolveForProtocol(host, p, serverProto.String()); ok {
						binding = &specific
					}
				}
			}
		}
	}

	if (serverProto == ProtoIMAP || serverProto == ProtoSMTP) && s.mailProxy != nil && binding != nil {
		// Close probe connection. The mail proxy establishes its own
		// upstream connection to manage STARTTLS and AUTH interception.
		_ = upstream.Close()
		// Pass nil for ready: SOCKS5 CONNECT already succeeded in the
		// parent handleWithDetection call.
		if err := s.mailProxy.HandleConnection(agentConn, dialAddrs, hostAddr, *binding, serverProto, nil); err != nil {
			log.Printf("[MAIL] handler error for %s: %v", hostAddr, err)
		}
		return
	}

	// No server-first protocol match or no mail proxy/binding available.
	// Relay with pre-read server bytes prepended to the upstream stream.
	var upstreamReader io.Reader = upstream
	if sn > 0 {
		upstreamReader = io.MultiReader(bytes.NewReader(serverBuf[:sn]), upstream)
	}
	upConn := &bufferedConn{Reader: upstreamReader, Conn: upstream}
	defer func() { _ = upstream.Close() }()
	bidirectionalRelay(agentConn, upConn)
}

// relayDirect connects to the first reachable address in dialAddrs and
// relays data bidirectionally with the agent connection.
func relayDirect(agent io.ReadWriteCloser, dialAddrs []string) {
	d := &net.Dialer{Timeout: connectTimeout}
	var upstream net.Conn
	var err error
	for _, addr := range dialAddrs {
		upstream, err = d.Dial("tcp", addr)
		if err == nil {
			break
		}
	}
	if err != nil {
		log.Printf("[DETECT] relay upstream dial failed for %v: %v", dialAddrs, err)
		return
	}
	defer func() { _ = upstream.Close() }()
	bidirectionalRelay(agent, upstream)
}

// bidirectionalRelay copies data between two connections until either
// direction closes or errors. Both connections are closed when done.
func bidirectionalRelay(a, b io.ReadWriter) {
	errc := make(chan error, 2)
	go func() { _, err := io.Copy(b, a); errc <- err }()
	go func() { _, err := io.Copy(a, b); errc <- err }()
	<-errc
	// One direction done. Close connections to unblock the other copy.
	if c, ok := a.(io.Closer); ok {
		_ = c.Close()
	}
	if c, ok := b.(io.Closer); ok {
		_ = c.Close()
	}
	<-errc
}

// handleAssociate is the custom SOCKS5 UDP ASSOCIATE handler registered via
// WithAssociateHandle. It creates a UDP listener, replies with its address,
// handleConnect is a custom SOCKS5 CONNECT handler that supports SNI-based
// policy deferral. For most connections it behaves identically to the default
// go-socks5 handler. When Allow() deferred the policy decision (ctxKeySNIDeferred),
// it peeks the first bytes from the client after CONNECT success to extract
// the TLS ClientHello SNI, re-evaluates policy with the recovered hostname,
// and blocks on the approval flow if needed before relaying data.
func (s *Server) handleConnect(ctx context.Context, writer io.Writer, request *socks5.Request) error {
	// SNI-deferred connections: extract SNI BEFORE dialing so the MITM proxy
	// uses the recovered hostname (not the raw IP) for the upstream TLS
	// ServerName. Without this, the upstream TLS handshake fails because the
	// real server's cert has DNS SANs (e.g. *.telegram.org) but not IP SANs.
	//
	// Hostname recovery priority:
	//   1. FQDN from SOCKS5 CONNECT (if client sends hostname)
	//   2. SNI from TLS ClientHello (this code path)
	//   3. DNS reverse cache (fallback for non-TLS)
	//   4. Raw IP (last resort)
	clientReader := request.Reader
	if deferred, _ := ctx.Value(ctxKeySNIDeferred).(bool); deferred {
		// Send SOCKS5 CONNECT success early so the client starts the TLS
		// handshake, allowing us to peek the ClientHello for SNI.
		// Use the destination address as bind address. The client expects
		// a valid address in the SOCKS5 reply, not 0.0.0.0:0.
		bindAddr := &net.TCPAddr{IP: request.DestAddr.IP, Port: request.DestAddr.Port}
		if sendErr := socks5.SendReply(writer, statute.RepSuccess, bindAddr); sendErr != nil {
			return fmt.Errorf("failed to send reply: %w", sendErr)
		}

		// Set a read deadline so SNI peeking doesn't block forever if the
		// client is slow to send the TLS ClientHello.
		if conn, ok := writer.(net.Conn); ok {
			conn.SetReadDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck
		}

		var allow bool
		clientReader, ctx, allow = s.sniPolicyCheckBeforeDial(ctx, request)
		if !allow {
			return nil
		}

		// Clear the read deadline before the relay phase. The deadline was
		// only needed for the SNI peek. Leaving it active would kill the
		// relay after 10 seconds, terminating long-running connections
		// (streaming API responses, tool calls, etc.).
		if conn, ok := writer.(net.Conn); ok {
			conn.SetReadDeadline(time.Time{}) //nolint:errcheck
		}

		// Dial with the updated context (FQDN now contains the SNI hostname).
		target, err := s.dial(ctx, "tcp", request.DestAddr.String())
		if err != nil {
			return fmt.Errorf("connect to %v failed: %w", request.RawDestAddr, err)
		}
		defer target.Close() //nolint:errcheck

		return s.relayData(clientReader, writer, target)
	}

	// Normal (non-deferred) path: dial first, then relay.
	target, err := s.dial(ctx, "tcp", request.DestAddr.String())
	if err != nil {
		msg := err.Error()
		resp := statute.RepHostUnreachable
		if strings.Contains(msg, "refused") {
			resp = statute.RepConnectionRefused
		} else if strings.Contains(msg, "network is unreachable") {
			resp = statute.RepNetworkUnreachable
		}
		if sendErr := socks5.SendReply(writer, resp, nil); sendErr != nil {
			return fmt.Errorf("failed to send reply: %w", sendErr)
		}
		return fmt.Errorf("connect to %v failed: %w", request.RawDestAddr, err)
	}
	defer target.Close() //nolint:errcheck

	if sendErr := socks5.SendReply(writer, statute.RepSuccess, target.LocalAddr()); sendErr != nil {
		return fmt.Errorf("failed to send reply: %w", sendErr)
	}

	return s.relayData(clientReader, writer, target)
}

// relayData bidirectionally copies data between the client and target.
//
// When the first direction finishes (either client or target closes), the
// writer (SOCKS5 connection) is closed to unblock the second goroutine.
// target is NOT closed here to avoid triggering broken pipe warnings in
// the MITM proxy. The caller's deferred target.Close() handles final
// cleanup. If the second goroutine is blocked reading from target (e.g.
// pending long-poll), a short deadline forces it to return instead of blocking
// indefinitely and leaking the SOCKS5 connection in CLOSE_WAIT state.
func (s *Server) relayData(clientReader io.Reader, writer io.Writer, target net.Conn) error {
	errCh := make(chan error, 2)
	go func() {
		_, cpErr := io.Copy(target, clientReader)
		if cw, ok := target.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite() //nolint:errcheck
		}
		errCh <- cpErr
	}()
	go func() {
		_, cpErr := io.Copy(writer, target)
		if cw, ok := writer.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite() //nolint:errcheck
		}
		errCh <- cpErr
	}()

	// Wait for the first direction to complete.
	e1 := <-errCh

	// Close writer to unblock goroutine 2 if it's stuck writing. Set a
	// read deadline on target to unblock goroutine 2 if it's stuck reading
	// (e.g. the MITM proxy waiting for a long-poll response). This avoids
	// closing target directly, which would trigger broken pipe warnings.
	if cl, ok := writer.(io.Closer); ok {
		cl.Close() //nolint:errcheck
	}
	target.SetReadDeadline(time.Now().Add(3 * time.Second)) //nolint:errcheck

	// Drain the second result so the goroutine is not leaked.
	e2 := <-errCh

	if e1 != nil {
		return e1
	}
	return e2
}

// sniPolicyCheckBeforeDial peeks the first bytes from the client to extract
// TLS SNI, re-evaluates policy with the recovered hostname, and updates the
// context FQDN so that the subsequent dial uses the hostname (not the raw IP)
// for the MITM upstream connection. Called BEFORE dial for SNI-deferred
// connections. Returns the client reader (with peeked bytes prepended), the
// updated context, and whether the connection should proceed.
func (s *Server) sniPolicyCheckBeforeDial(ctx context.Context, request *socks5.Request) (io.Reader, context.Context, bool) {
	buf, sni, err := peekSNI(request.Reader, 8192)
	if err != nil || sni == "" {
		// Not TLS or no SNI. Fall through with original data and IP-based context.
		hexPrefix := ""
		if len(buf) >= 6 {
			hexPrefix = fmt.Sprintf(" first6=%02x", buf[:6])
		}
		log.Printf("[SNI-PEEK] no SNI extracted (err=%v, bufLen=%d, sni=%q%s)", err, len(buf), sni, hexPrefix)
		if len(buf) > 0 {
			return io.MultiReader(bytes.NewReader(buf), request.Reader), ctx, true
		}
		return request.Reader, ctx, true
	}

	sni = strings.TrimRight(sni, ".")
	dest := request.DestAddr.String()
	ipStr := strings.Split(dest, ":")[0]
	port := request.DestAddr.Port

	log.Printf("[SNI] %s -> %s:%d (recovered hostname via TLS ClientHello)", ipStr, sni, port)

	// Update context FQDN so dial() uses the hostname for the MITM upstream.
	ctx = context.WithValue(ctx, ctxKeyFQDN, sni)

	// Populate DNS reverse cache for future connections.
	if s.dnsInterceptor != nil {
		s.dnsInterceptor.StoreReverse(ipStr, sni)
	}

	// Re-evaluate policy with the SNI hostname.
	eng, _ := ctx.Value(ctxKeyEngine).(*policy.Engine)
	if eng == nil {
		eng = s.rules.engine.Load()
	}
	verdict, matchSource := eng.EvaluateDetailed(sni, port)
	reader := io.MultiReader(bytes.NewReader(buf), request.Reader)

	switch verdict {
	case policy.Allow:
		log.Printf("[SNI->ALLOW] %s:%d (hostname %s matched allow rule)", ipStr, port, sni)
		// Explicit allow rule: skip the per-request check entirely.
		if matchSource == policy.RuleMatch {
			ctx = context.WithValue(ctx, ctxKeySkipPerRequest, true)
		} else if s.rules.broker == nil {
			ctx = context.WithValue(ctx, ctxKeySkipPerRequest, true)
		} else {
			checker := NewRequestPolicyChecker(s.rules.engine, s.rules.broker,
				WithPersist(s.rules.buildPersistFunc()),
			)
			ctx = context.WithValue(ctx, ctxKeyPerRequestPolicy, checker)
		}
		return reader, ctx, true
	case policy.Deny:
		log.Printf("[SNI->DENY] %s:%d (hostname %s matched deny rule)", ipStr, port, sni)
		return nil, ctx, false
	case policy.Ask:
		if s.rules.broker == nil {
			log.Printf("[SNI->DENY] %s:%d (hostname %s: ask treated as deny, no broker)", ipStr, port, sni)
			return nil, ctx, false
		}
		// Auto-allow the connection and defer approval to per-request
		// checks where the HTTP method and path are visible.
		log.Printf("[SNI->DEFER] %s:%d (hostname %s: approval deferred to per-request)", ipStr, port, sni)
		checker := NewRequestPolicyChecker(s.rules.engine, s.rules.broker,
			WithPersist(s.rules.buildPersistFunc()),
		)
		ctx = context.WithValue(ctx, ctxKeyPerRequestPolicy, checker)
		return reader, ctx, true
	default:
		log.Printf("[SNI->DENY] %s:%d (hostname %s: default deny)", ipStr, port, sni)
		return nil, ctx, false
	}
}

// then dispatches datagrams to the DNSInterceptor (port 53) or UDPRelay
// (all other ports). The handler blocks until the TCP control connection
// closes, at which point all UDP sessions are cleaned up.
func (s *Server) handleAssociate(_ context.Context, writer io.Writer, request *socks5.Request) error {
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
		_ = bindLn.Close()
		return fmt.Errorf("send reply: %w", err)
	}

	// Track upstream UDP sessions for non-DNS traffic.
	var mu sync.Mutex
	sessions := make(map[string]*udpSession)

	// Ensure bindLn is closed exactly once regardless of which goroutine
	// exits first (dispatch loop vs TCP control connection reader).
	var closeBindOnce sync.Once
	closeBind := func() { closeBindOnce.Do(func() { _ = bindLn.Close() }) }

	// Start the datagram dispatch loop in a goroutine.
	go func() {
		defer func() {
			mu.Lock()
			for _, sess := range sessions {
				if s.quicProxy != nil {
					s.quicProxy.UnregisterExpectedHost(sess.upstream.LocalAddr().String())
				}
				_ = sess.upstream.Close()
			}
			mu.Unlock()
			closeBind()
		}()

		buf := make([]byte, 65535)
		for {
			_ = bindLn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, srcAddr, readErr := bindLn.ReadFrom(buf)
			if readErr != nil {
				var ne net.Error
				if errors.As(readErr, &ne) && ne.Timeout() {
					// Clean up expired sessions on timeout.
					mu.Lock()
					now := time.Now()
					for key, sess := range sessions {
						if now.Sub(sess.lastSeen) > udpSessionTimeout {
							if s.quicProxy != nil {
								s.quicProxy.UnregisterExpectedHost(sess.upstream.LocalAddr().String())
							}
							_ = sess.upstream.Close()
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
						checker, drop := s.resolveQUICPolicy(dest, port)
						if drop {
							continue
						}

						upstream, listenErr := net.ListenPacket("udp", "127.0.0.1:0")
						if listenErr != nil {
							log.Printf("[QUIC] create upstream for %s: %v", sessionKey, listenErr)
							continue
						}
						// Register expected host so the QUIC proxy can verify
						// that the TLS SNI matches the policy-checked destination.
						// A non-nil checker enables per-HTTP/3-request approval
						// for ask-rule matches. Allow with RuleMatch passes nil
						// (fast path, no per-request check).
						if checker != nil {
							s.quicProxy.RegisterExpectedHostWithChecker(upstream.LocalAddr().String(), dest, port, checker)
						} else {
							s.quicProxy.RegisterExpectedHost(upstream.LocalAddr().String(), dest, port)
						}
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
		_ = upstream.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, srcAddr, err := upstream.ReadFrom(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
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
// resolveQUICPolicy evaluates QUIC-specific policy for a destination and
// handles the Ask approval flow. Returns a per-request checker (nil for
// explicit allow fast path) and a drop flag. When drop is true the caller
// should discard the packet without creating a session.
func (s *Server) resolveQUICPolicy(dest string, port int) (checker *RequestPolicyChecker, drop bool) {
	verdict, matchSource := s.udpRelay.engine.Load().EvaluateQUICDetailed(dest, port)

	if verdict == policy.Deny {
		if s.udpRelay.audit != nil {
			if logErr := s.udpRelay.audit.Log(audit.Event{
				Destination: dest,
				Port:        port,
				Protocol:    ProtoQUIC.String(),
				Verdict:     "deny",
				Reason:      "quic denied by policy",
			}); logErr != nil {
				log.Printf("audit log write error: %v", logErr)
			}
		}
		return nil, true
	}

	if verdict == policy.Ask {
		if s.rules.broker == nil {
			log.Printf("[QUIC->DENY] %s:%d (ask treated as deny, no broker)", dest, port)
			if s.udpRelay.audit != nil {
				if logErr := s.udpRelay.audit.Log(audit.Event{
					Destination: dest,
					Port:        port,
					Protocol:    ProtoQUIC.String(),
					Verdict:     "deny",
					Reason:      "ask treated as deny (no approval broker)",
				}); logErr != nil {
					log.Printf("audit log write error: %v", logErr)
				}
			}
			return nil, true
		}

		eng := s.udpRelay.engine.Load()
		timeout := time.Duration(eng.TimeoutSec) * time.Second
		log.Printf("[QUIC->ASK] %s:%d (waiting for approval)", dest, port)
		resp, reqErr := s.rules.broker.Request(dest, port, ProtoQUIC.String(), timeout)
		if reqErr != nil {
			log.Printf("[QUIC->DENY] %s:%d (approval timeout: %v)", dest, port, reqErr)
			return nil, true
		}

		switch resp {
		case channel.ResponseAllowOnce:
			log.Printf("[QUIC->ALLOW] %s:%d (user approved once)", dest, port)
			return NewRequestPolicyChecker(s.rules.engine, s.rules.broker,
				WithPersist(s.rules.buildPersistFunc()),
				WithSeedCredits(1),
			), false
		case channel.ResponseAlwaysAllow:
			log.Printf("[QUIC->ALLOW+SAVE] %s:%d (user approved always)", dest, port)
			if persist := s.rules.buildPersistFunc(); persist != nil {
				persist(PersistAllow, dest, port)
			}
			return nil, false
		case channel.ResponseAlwaysDeny:
			log.Printf("[QUIC->DENY+SAVE] %s:%d (user denied always)", dest, port)
			if persist := s.rules.buildPersistFunc(); persist != nil {
				persist(PersistDeny, dest, port)
			}
			return nil, true
		default:
			log.Printf("[QUIC->DENY] %s:%d (user denied)", dest, port)
			return nil, true
		}
	}

	// Allow with default verdict: attach a checker so per-request
	// evaluation picks up policy changes.
	if verdict == policy.Allow && matchSource == policy.DefaultVerdict {
		return NewRequestPolicyChecker(s.rules.engine, s.rules.broker,
			WithPersist(s.rules.buildPersistFunc()),
			WithSeedCredits(1),
		), false
	}

	// Explicit allow: fast path, no per-request check needed.
	return nil, false
}

func (s *Server) relayQUICResponses(upstream net.PacketConn, relay *net.UDPConn, clientAddr net.Addr, originalDst *net.UDPAddr) {
	buf := make([]byte, 65535)
	for {
		_ = upstream.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, _, err := upstream.ReadFrom(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
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

// UpdateInspectRules recompiles content inspection rules from the engine and
// atomically swaps them into the WebSocket and QUIC proxies. Call this after
// StoreEngine so SIGHUP-reloaded block/redact patterns take effect for
// in-flight WebSocket and QUIC connections.
func (s *Server) UpdateInspectRules(eng *policy.Engine) {
	var wsBlock []WSBlockRuleConfig
	var wsRedact []WSRedactRuleConfig
	for _, r := range eng.InspectBlockRules {
		wsBlock = append(wsBlock, WSBlockRuleConfig{Pattern: r.Pattern, Name: r.Name})
	}
	for _, r := range eng.InspectRedactRules {
		wsRedact = append(wsRedact, WSRedactRuleConfig{Pattern: r.Pattern, Replacement: r.Replacement, Name: r.Name})
	}
	if s.addon != nil && s.addon.wsProxy != nil {
		if err := s.addon.wsProxy.UpdateRules(wsBlock, wsRedact); err != nil {
			log.Printf("update ws inspect rules: %v", err)
		}
	}
	if s.quicProxy != nil {
		var quicBlock []QUICBlockRuleConfig
		var quicRedact []QUICRedactRuleConfig
		for _, r := range eng.InspectBlockRules {
			quicBlock = append(quicBlock, QUICBlockRuleConfig{Pattern: r.Pattern, Name: r.Name})
		}
		for _, r := range eng.InspectRedactRules {
			quicRedact = append(quicRedact, QUICRedactRuleConfig{Pattern: r.Pattern, Replacement: r.Replacement, Name: r.Name})
		}
		if err := s.quicProxy.UpdateRules(quicBlock, quicRedact); err != nil {
			log.Printf("update quic inspect rules: %v", err)
		}
	}
}

// StoreResolver atomically stores a new binding resolver. The caller must
// hold ReloadMu() when concurrent mutations are possible. The MITM addon
// shares the same atomic pointer so both the dial function and MITM proxy
// see the updated bindings.
func (s *Server) StoreResolver(r *vault.BindingResolver) {
	s.resolver.Store(r)
}

// UpdateOAuthIndex rebuilds the OAuth token URL index from credential
// metadata. Call this after StoreResolver in the SIGHUP reload path or
// after Telegram credential mutations so the response handler detects
// new or removed OAuth token endpoints.
func (s *Server) UpdateOAuthIndex(metas []store.CredentialMeta) {
	if s.addon != nil {
		s.addon.UpdateOAuthIndex(metas)
	}
}

// SetOnOAuthRefresh configures a callback on the addon that is invoked
// after an OAuth token refresh is persisted to the vault. The callback
// receives the credential name so the caller can re-inject updated phantom
// env vars into the agent container.
func (s *Server) SetOnOAuthRefresh(fn func(credName string)) {
	if s.addon != nil {
		s.addon.SetOnOAuthRefresh(fn)
	}
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
	if s.mitmProxy != nil {
		_ = s.mitmProxy.Close()
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
	if s.mitmProxy != nil {
		_ = s.mitmProxy.Close()
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
