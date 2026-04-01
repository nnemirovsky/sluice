package proxy

import (
	"context"
	"fmt"
	"log"
	"net"

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
}

type contextKey string

const ctxKeyProtocol contextKey = "protocol"

// ProtocolFromContext retrieves the detected protocol from the request context.
func ProtocolFromContext(ctx context.Context) Protocol {
	if v, ok := ctx.Value(ctxKeyProtocol).(Protocol); ok {
		return v
	}
	return ProtoGeneric
}

type policyRuleSet struct {
	engine *policy.Engine
	audit  *audit.FileLogger
}

func (r *policyRuleSet) Allow(ctx context.Context, req *socks5.Request) (context.Context, bool) {
	dest := req.DestAddr.FQDN
	if dest == "" {
		if req.DestAddr.IP != nil {
			dest = req.DestAddr.IP.String()
		} else {
			return ctx, false
		}
	}
	port := req.DestAddr.Port

	verdict := r.engine.Evaluate(dest, port)

	if r.audit != nil {
		if err := r.audit.Log(audit.Event{
			Destination: dest,
			Port:        port,
			Verdict:     verdict.String(),
		}); err != nil {
			log.Printf("audit log write error: %v", err)
		}
	}

	switch verdict {
	case policy.Allow:
		proto := DetectProtocol(port)
		ctx = context.WithValue(ctx, ctxKeyProtocol, proto)
		return ctx, true
	case policy.Ask:
		log.Printf("[ASK->DENY] %s:%d (Telegram not configured)", dest, port)
		return ctx, false
	default:
		return ctx, false
	}
}

// New creates a new SOCKS5 proxy server bound to the configured listen address.
func New(cfg Config) (*Server, error) {
	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}

	rules := &policyRuleSet{engine: cfg.Policy, audit: cfg.Audit}

	socksCfg := &socks5.Config{
		Rules: rules,
	}
	socksServer, err := socks5.New(socksCfg)
	if err != nil {
		ln.Close()
		return nil, fmt.Errorf("socks5: %w", err)
	}

	return &Server{
		listener: ln,
		socks:    socksServer,
	}, nil
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
