// Package http provides an HTTP webhook channel implementation satisfying the
// channel.Channel interface. Approval requests are delivered via HTTP POST to
// a configured webhook URL with HMAC-SHA256 signatures. Supports both sync
// (verdict in response body) and async (202 Accepted, callback via API) paths.
package http

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/nemirovsky/sluice/internal/channel"
)

// WebhookPayload is the JSON body sent to the webhook URL for approval requests.
type WebhookPayload struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Destination string    `json:"destination"`
	Port        int       `json:"port"`
	Protocol    string    `json:"protocol,omitempty"`
	Tool        string    `json:"tool,omitempty"`
	ToolArgs    string    `json:"tool_args,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
}

// NotifyPayload is the JSON body sent for fire-and-forget notifications.
type NotifyPayload struct {
	Type      string    `json:"type"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}

// CancelPayload is the JSON body sent when an approval is cancelled.
type CancelPayload struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Timestamp time.Time `json:"timestamp"`
}

// WebhookResponse is the expected response body for sync approval resolution.
type WebhookResponse struct {
	Verdict string `json:"verdict"`
}

// Config holds the configuration for creating an HTTPChannel.
type Config struct {
	WebhookURL    string
	WebhookSecret string
	HTTPClient    *http.Client
}

// HTTPChannel implements channel.Channel for HTTP webhook delivery.
type HTTPChannel struct { //nolint:revive // stuttering accepted for clarity
	webhookURL    string
	webhookSecret string
	client        *http.Client
	broker        *channel.Broker
	pending       sync.Map // request ID -> struct{} for tracking pending requests
	done          chan struct{}
	stopOnce      sync.Once

	maxRetries     int
	baseBackoff    time.Duration
	requestTimeout time.Duration
}

// NewHTTPChannel creates an HTTPChannel with the given configuration.
func NewHTTPChannel(cfg Config) (*HTTPChannel, error) {
	if cfg.WebhookURL == "" {
		return nil, fmt.Errorf("webhook_url is required")
	}
	u, err := url.Parse(cfg.WebhookURL)
	if err != nil {
		return nil, fmt.Errorf("invalid webhook_url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("webhook_url scheme must be http or https, got %q", u.Scheme)
	}

	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}

	return &HTTPChannel{
		webhookURL:     cfg.WebhookURL,
		webhookSecret:  cfg.WebhookSecret,
		client:         client,
		done:           make(chan struct{}),
		maxRetries:     3,
		baseBackoff:    500 * time.Millisecond,
		requestTimeout: 30 * time.Second,
	}, nil
}

// SetBroker sets the broker reference for resolving approval requests.
func (h *HTTPChannel) SetBroker(b *channel.Broker) {
	h.broker = b
}

// RequestApproval delivers an approval request to the webhook URL (non-blocking).
// If the webhook responds with 200 and a verdict, the approval is resolved
// synchronously. If it responds with 202, the approval waits for an async
// callback via the API's resolve endpoint.
func (h *HTTPChannel) RequestApproval(_ context.Context, req channel.ApprovalRequest) error {
	h.pending.Store(req.ID, struct{}{})
	go h.deliverApproval(req)
	return nil
}

func (h *HTTPChannel) deliverApproval(req channel.ApprovalRequest) {
	if h.broker != nil && !h.broker.HasWaiter(req.ID) {
		h.pending.Delete(req.ID)
		return
	}

	payload := WebhookPayload{
		ID:          req.ID,
		Type:        "approval",
		Destination: req.Destination,
		Port:        req.Port,
		Protocol:    req.Protocol,
		ToolArgs:    req.ToolArgs,
		Timestamp:   req.CreatedAt,
	}
	if req.Protocol == "mcp" {
		payload.Tool = req.Destination
	}

	body, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[WARN] http channel: failed to marshal approval payload: %v", err)
		h.resolveDenyOnSingleChannel(req.ID)
		h.pending.Delete(req.ID)
		return
	}

	resp, err := h.postWithRetry(body)
	if err != nil {
		log.Printf("[WARN] http channel: failed to deliver approval %s: %v", req.ID, err)
		h.resolveDenyOnSingleChannel(req.ID)
		h.pending.Delete(req.ID)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		// Sync path: response body contains the verdict.
		var wr WebhookResponse
		respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if readErr != nil {
			log.Printf("[WARN] http channel: failed to read sync response for %s: %v", req.ID, readErr)
			h.resolveDenyOnSingleChannel(req.ID)
			h.pending.Delete(req.ID)
			return
		}
		if err := json.Unmarshal(respBody, &wr); err != nil {
			log.Printf("[WARN] http channel: invalid sync response for %s: %v", req.ID, err)
			h.resolveDenyOnSingleChannel(req.ID)
			h.pending.Delete(req.ID)
			return
		}
		verdict := parseVerdict(wr.Verdict)
		if h.broker != nil {
			h.broker.Resolve(req.ID, verdict)
		}
		h.pending.Delete(req.ID)

	case http.StatusAccepted:
		// Async path: webhook acknowledged, will call back via API.
		// Leave the request pending. The broker timeout or API callback
		// will eventually resolve it.

	default:
		log.Printf("[WARN] http channel: unexpected status %d for approval %s", resp.StatusCode, req.ID)
		h.resolveDenyOnSingleChannel(req.ID)
		h.pending.Delete(req.ID)
	}
}

// CancelApproval sends a cancellation notification to the webhook and cleans
// up the pending request.
func (h *HTTPChannel) CancelApproval(id string) error {
	if _, ok := h.pending.LoadAndDelete(id); !ok {
		return nil
	}

	payload := CancelPayload{
		ID:        id,
		Type:      "cancel",
		Timestamp: time.Now().UTC(),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal cancel payload: %w", err)
	}

	// Fire and forget. Use a single attempt (no retry) for cancellations.
	go func() {
		resp, postErr := h.post(body)
		if postErr != nil {
			log.Printf("[WARN] http channel: failed to deliver cancel for %s: %v", id, postErr)
			return
		}
		_ = resp.Body.Close()
	}()
	return nil
}

// Commands returns nil because HTTP webhooks do not support incoming commands.
func (h *HTTPChannel) Commands() <-chan channel.Command {
	return nil
}

// Notify sends a one-way notification to the webhook URL (fire and forget).
func (h *HTTPChannel) Notify(_ context.Context, msg string) error {
	payload := NotifyPayload{
		Type:      "notification",
		Message:   msg,
		Timestamp: time.Now().UTC(),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal notify payload: %w", err)
	}

	go func() {
		resp, postErr := h.postWithRetry(body)
		if postErr != nil {
			log.Printf("[WARN] http channel: failed to deliver notification: %v", postErr)
			return
		}
		_ = resp.Body.Close()
	}()
	return nil
}

// Start is a no-op for the HTTP channel. Unlike Telegram which polls for
// updates, the HTTP channel is purely push-based.
func (h *HTTPChannel) Start() error {
	return nil
}

// Stop closes the channel. Outstanding deliveries may be abandoned.
func (h *HTTPChannel) Stop() {
	h.stopOnce.Do(func() {
		close(h.done)
	})
}

// Type returns channel.ChannelHTTP.
func (h *HTTPChannel) Type() channel.ChannelType {
	return channel.ChannelHTTP
}

// post sends a signed POST request to the webhook URL (single attempt).
func (h *HTTPChannel) post(body []byte) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), h.requestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.webhookURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	if h.webhookSecret != "" {
		sig := computeHMAC(body, h.webhookSecret)
		req.Header.Set("X-Sluice-Signature", "sha256="+sig)
	}

	return h.client.Do(req)
}

// postWithRetry sends a POST with up to maxRetries attempts using exponential backoff.
func (h *HTTPChannel) postWithRetry(body []byte) (*http.Response, error) {
	var lastErr error
	for attempt := 0; attempt < h.maxRetries; attempt++ {
		// Check if the channel has been stopped.
		select {
		case <-h.done:
			return nil, fmt.Errorf("channel stopped")
		default:
		}

		resp, err := h.post(body)
		if err == nil {
			// Treat 5xx as retriable.
			if resp.StatusCode >= 500 {
				_ = resp.Body.Close()
				lastErr = fmt.Errorf("server error: %d", resp.StatusCode)
			} else {
				return resp, nil
			}
		} else {
			lastErr = err
		}

		if attempt < h.maxRetries-1 {
			backoff := h.baseBackoff * time.Duration(math.Pow(2, float64(attempt)))
			select {
			case <-time.After(backoff):
			case <-h.done:
				return nil, fmt.Errorf("channel stopped during backoff")
			}
		}
	}
	return nil, fmt.Errorf("all %d attempts failed: %w", h.maxRetries, lastErr)
}

// resolveDenyOnSingleChannel resolves the request as Deny when this is the
// only channel. In multi-channel setups, another channel may still deliver.
func (h *HTTPChannel) resolveDenyOnSingleChannel(id string) {
	if h.broker != nil && len(h.broker.Channels()) <= 1 {
		h.broker.Resolve(id, channel.ResponseDeny)
	}
}

// computeHMAC returns the hex-encoded HMAC-SHA256 of body using the given secret.
func computeHMAC(body []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// parseVerdict converts a string verdict to a channel.Response.
func parseVerdict(v string) channel.Response {
	switch v {
	case "allow", "allow_once":
		return channel.ResponseAllowOnce
	case "always_allow":
		return channel.ResponseAlwaysAllow
	case "deny":
		return channel.ResponseDeny
	default:
		return channel.ResponseDeny
	}
}
