package api

import (
	"encoding/json"
	"net/http"
	"os"

	"github.com/nemirovsky/sluice/internal/channel"
	"github.com/nemirovsky/sluice/internal/proxy"
	"github.com/nemirovsky/sluice/internal/store"
)

// Server implements the generated ServerInterface for the sluice REST API.
// Only approval, status, and health handlers are implemented here (Task 2).
// Remaining handlers are added in subsequent tasks and embed Unimplemented
// to satisfy the interface.
type Server struct {
	Unimplemented
	store     *store.Store
	broker    *channel.Broker
	proxySrv  *proxy.Server
	auditPath string
}

// NewServer creates a new API server.
func NewServer(st *store.Store, broker *channel.Broker, proxySrv *proxy.Server, auditPath string) *Server {
	return &Server{
		store:     st,
		broker:    broker,
		proxySrv:  proxySrv,
		auditPath: auditPath,
	}
}

// GetHealthz returns 200 when the proxy is listening.
func (s *Server) GetHealthz(w http.ResponseWriter, r *http.Request) {
	status := "ok"
	code := http.StatusOK
	if s.proxySrv == nil || !s.proxySrv.IsListening() {
		status = "not ready"
		code = http.StatusServiceUnavailable
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(HealthResponse{Status: status})
}

// GetApiApprovals returns pending approval requests from the broker.
func (s *Server) GetApiApprovals(w http.ResponseWriter, r *http.Request) {
	var approvals []ApprovalRequest
	if s.broker != nil {
		pending := s.broker.PendingRequests()
		approvals = make([]ApprovalRequest, len(pending))
		for i, p := range pending {
			approvals[i] = ApprovalRequest{
				Id:          p.ID,
				Destination: p.Destination,
				Port:        p.Port,
				CreatedAt:   p.CreatedAt,
			}
		}
	}
	if approvals == nil {
		approvals = []ApprovalRequest{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(approvals)
}

// PostApiApprovalsIdResolve resolves a pending approval request.
func (s *Server) PostApiApprovalsIdResolve(w http.ResponseWriter, r *http.Request, id string) {
	var req ResolveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "")
		return
	}

	if !req.Verdict.Valid() {
		writeError(w, http.StatusBadRequest, "invalid verdict", "")
		return
	}

	if s.broker == nil {
		writeError(w, http.StatusServiceUnavailable, "no approval broker configured", "")
		return
	}

	var resp channel.Response
	switch req.Verdict {
	case ResolveRequestVerdictAllowOnce:
		resp = channel.ResponseAllowOnce
	case ResolveRequestVerdictAlwaysAllow:
		resp = channel.ResponseAlwaysAllow
	case ResolveRequestVerdictDeny:
		resp = channel.ResponseDeny
	}

	if !s.broker.Resolve(id, resp) {
		writeError(w, http.StatusNotFound, "approval request not found or already resolved", "")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ResolveResponse{
		Id:      id,
		Verdict: string(req.Verdict),
	})
}

// GetApiStatus returns proxy status and channel information.
func (s *Server) GetApiStatus(w http.ResponseWriter, r *http.Request) {
	listening := s.proxySrv != nil && s.proxySrv.IsListening()

	pendingCount := 0
	if s.broker != nil {
		pendingCount = s.broker.PendingCount()
	}

	var channelStatuses []ChannelStatus
	if s.broker != nil {
		for _, ch := range s.broker.Channels() {
			var typeName ChannelStatusType
			switch ch.Type() {
			case channel.ChannelTelegram:
				typeName = ChannelStatusTypeTelegram
			case channel.ChannelHTTP:
				typeName = ChannelStatusTypeHttp
			}
			channelStatuses = append(channelStatuses, ChannelStatus{
				Type:    typeName,
				Enabled: true,
			})
		}
	}
	if channelStatuses == nil {
		channelStatuses = []ChannelStatus{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(StatusResponse{
		ProxyListening:   listening,
		PendingApprovals: pendingCount,
		Channels:         channelStatuses,
	})
}

// BearerAuthMiddleware validates the Authorization header against SLUICE_API_TOKEN.
// If the env var is not set, all /api/* requests return 403.
func BearerAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// /healthz bypasses auth (no security scheme in OpenAPI spec).
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}

		token := os.Getenv("SLUICE_API_TOKEN")
		if token == "" {
			writeError(w, http.StatusForbidden, "API token not configured", "unauthorized")
			return
		}

		auth := r.Header.Get("Authorization")
		if auth == "" {
			writeError(w, http.StatusUnauthorized, "missing authorization header", "unauthorized")
			return
		}

		const prefix = "Bearer "
		if len(auth) < len(prefix) || auth[:len(prefix)] != prefix {
			writeError(w, http.StatusUnauthorized, "invalid authorization format", "unauthorized")
			return
		}

		if auth[len(prefix):] != token {
			writeError(w, http.StatusUnauthorized, "invalid token", "unauthorized")
			return
		}

		next.ServeHTTP(w, r)
	})
}

// ChannelGateMiddleware returns 403 on /api/* routes when no HTTP channel
// (type=1) is enabled in the store. /healthz is always accessible.
// Auth check runs before channel check (via middleware ordering) so bad
// tokens never reveal channel state.
func ChannelGateMiddleware(st *store.Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/healthz" {
				next.ServeHTTP(w, r)
				return
			}

			channels, err := st.ListChannels()
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to check channel state", "")
				return
			}

			httpEnabled := false
			for _, ch := range channels {
				if ch.Type == int(channel.ChannelHTTP) && ch.Enabled {
					httpEnabled = true
					break
				}
			}

			if !httpEnabled {
				writeError(w, http.StatusForbidden, "HTTP channel is not enabled", "channel_disabled")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, msg string, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	resp := ErrorResponse{Error: msg}
	if code != "" {
		resp.Code = &code
	}
	_ = json.NewEncoder(w).Encode(resp)
}
