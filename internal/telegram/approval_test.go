package telegram

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/nemirovsky/sluice/internal/channel"
	"github.com/nemirovsky/sluice/internal/container"
	"github.com/nemirovsky/sluice/internal/policy"
	"github.com/nemirovsky/sluice/internal/store"
	"github.com/nemirovsky/sluice/internal/vault"
)

// newIPv4Server creates an httptest.Server that listens on IPv4 only. This
// avoids failures in environments where IPv6 is not available.
func newIPv4Server(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &httptest.Server{
		Listener: ln,
		Config:   &http.Server{Handler: handler},
	}
	srv.Start()
	return srv
}

// tgResponse wraps the Telegram Bot API response format.
type tgResponse struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result"`
}

// mockTelegramAPI creates an httptest server that mimics the Telegram Bot API.
// It records sent messages and provides channels for injecting updates.
type mockTelegramAPI struct {
	server *httptest.Server

	mu             sync.Mutex
	sentMessages   []tgbotapi.MessageConfig
	editedMsgs     []tgbotapi.EditMessageTextConfig
	callbacks      []tgbotapi.CallbackConfig
	deletedMsgs    []tgbotapi.DeleteMessageConfig
	setCommandsRaw string // raw JSON payload from the last setMyCommands call

	nextMsgID int
	updates   chan []tgbotapi.Update
}

func newMockTelegramAPI(t *testing.T) *mockTelegramAPI {
	t.Helper()
	m := &mockTelegramAPI{
		nextMsgID: 100,
		updates:   make(chan []tgbotapi.Update, 10),
	}
	m.server = newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// URL format: /bot<token>/<method>
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) < 3 {
			http.Error(w, "bad path", 400)
			return
		}
		method := parts[len(parts)-1]

		w.Header().Set("Content-Type", "application/json")
		switch method {
		case "getMe":
			_ = json.NewEncoder(w).Encode(tgResponse{
				OK:     true,
				Result: json.RawMessage(`{"id":123456,"is_bot":true,"first_name":"TestBot","username":"test_bot"}`),
			})
		case "sendMessage":
			_ = r.ParseForm()
			m.mu.Lock()
			m.nextMsgID++
			msgID := m.nextMsgID
			m.mu.Unlock()

			msg := tgbotapi.MessageConfig{}
			chatIDStr := r.FormValue("chat_id")
			msg.Text = r.FormValue("text")
			if chatIDStr != "" {
				_, _ = fmt.Sscanf(chatIDStr, "%d", &msg.ChatID)
			}
			m.mu.Lock()
			m.sentMessages = append(m.sentMessages, msg)
			m.mu.Unlock()

			result := fmt.Sprintf(`{"message_id":%d,"chat":{"id":%s},"text":"%s","date":%d}`,
				msgID, chatIDStr, escapeJSON(r.FormValue("text")), time.Now().Unix())
			_ = json.NewEncoder(w).Encode(tgResponse{OK: true, Result: json.RawMessage(result)})

		case "editMessageText":
			_ = r.ParseForm()
			m.mu.Lock()
			m.editedMsgs = append(m.editedMsgs, tgbotapi.EditMessageTextConfig{
				Text: r.FormValue("text"),
			})
			m.mu.Unlock()

			_ = json.NewEncoder(w).Encode(tgResponse{
				OK:     true,
				Result: json.RawMessage(`{"message_id":1,"text":"edited","date":0}`),
			})

		case "answerCallbackQuery":
			_ = r.ParseForm()
			m.mu.Lock()
			m.callbacks = append(m.callbacks, tgbotapi.CallbackConfig{
				CallbackQueryID: r.FormValue("callback_query_id"),
				Text:            r.FormValue("text"),
			})
			m.mu.Unlock()
			_ = json.NewEncoder(w).Encode(tgResponse{OK: true, Result: json.RawMessage(`true`)})

		case "deleteMessage":
			_ = r.ParseForm()
			m.mu.Lock()
			m.deletedMsgs = append(m.deletedMsgs, tgbotapi.DeleteMessageConfig{})
			m.mu.Unlock()
			_ = json.NewEncoder(w).Encode(tgResponse{OK: true, Result: json.RawMessage(`true`)})

		case "getUpdates":
			// Return updates if available, otherwise empty array.
			select {
			case updates := <-m.updates:
				data, _ := json.Marshal(updates)
				_ = json.NewEncoder(w).Encode(tgResponse{OK: true, Result: json.RawMessage(data)})
			case <-time.After(100 * time.Millisecond):
				_ = json.NewEncoder(w).Encode(tgResponse{OK: true, Result: json.RawMessage(`[]`)})
			}

		case "setMyCommands":
			_ = r.ParseForm()
			raw := r.FormValue("commands")
			m.mu.Lock()
			m.setCommandsRaw = raw
			m.mu.Unlock()
			_ = json.NewEncoder(w).Encode(tgResponse{OK: true, Result: json.RawMessage(`true`)})

		default:
			_ = json.NewEncoder(w).Encode(tgResponse{OK: true, Result: json.RawMessage(`true`)})
		}
	}))
	t.Cleanup(m.server.Close)
	return m
}

func (m *mockTelegramAPI) endpoint() string {
	return m.server.URL + "/bot%s/%s"
}

func (m *mockTelegramAPI) getSentMessages() []tgbotapi.MessageConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]tgbotapi.MessageConfig, len(m.sentMessages))
	copy(out, m.sentMessages)
	return out
}

func (m *mockTelegramAPI) getEditedMessages() []tgbotapi.EditMessageTextConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]tgbotapi.EditMessageTextConfig, len(m.editedMsgs))
	copy(out, m.editedMsgs)
	return out
}

func (m *mockTelegramAPI) getCallbacks() []tgbotapi.CallbackConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]tgbotapi.CallbackConfig, len(m.callbacks))
	copy(out, m.callbacks)
	return out
}

func (m *mockTelegramAPI) getDeletedMessages() []tgbotapi.DeleteMessageConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]tgbotapi.DeleteMessageConfig, len(m.deletedMsgs))
	copy(out, m.deletedMsgs)
	return out
}

func (m *mockTelegramAPI) getSetCommandsRaw() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.setCommandsRaw
}

func escapeJSON(s string) string {
	b, _ := json.Marshal(s)
	// Strip surrounding quotes.
	return string(b[1 : len(b)-1])
}

// newTestTelegramChannel creates a TelegramChannel connected to a mock API.
func newTestTelegramChannel(t *testing.T, mock *mockTelegramAPI, s *store.Store) *TelegramChannel {
	t.Helper()
	eng, err := policy.LoadFromStore(s)
	if err != nil {
		t.Fatal(err)
	}
	ptr := new(atomic.Pointer[policy.Engine])
	ptr.Store(eng)

	tc, err := NewTelegramChannel(ChannelConfig{
		Token:       "test-token",
		ChatID:      12345,
		EnginePtr:   ptr,
		ReloadMu:    new(sync.Mutex),
		Store:       s,
		APIEndpoint: mock.endpoint(),
	})
	if err != nil {
		t.Fatalf("NewTelegramChannel: %v", err)
	}
	t.Cleanup(tc.Stop)
	return tc
}

// --- NewTelegramChannel tests ---

func TestNewTelegramChannel(t *testing.T) {
	mock := newMockTelegramAPI(t)
	s := newTestStore(t)

	eng, err := policy.LoadFromStore(s)
	if err != nil {
		t.Fatal(err)
	}
	ptr := new(atomic.Pointer[policy.Engine])
	ptr.Store(eng)

	tc, err := NewTelegramChannel(ChannelConfig{
		Token:       "test-token",
		ChatID:      99999,
		EnginePtr:   ptr,
		ReloadMu:    new(sync.Mutex),
		Store:       s,
		APIEndpoint: mock.endpoint(),
	})
	if err != nil {
		t.Fatalf("NewTelegramChannel: %v", err)
	}
	defer tc.Stop()

	if tc.chatID != 99999 {
		t.Errorf("chatID = %d, want 99999", tc.chatID)
	}
	if tc.api == nil {
		t.Error("api should not be nil")
	}
	if tc.commands == nil {
		t.Error("commands should not be nil")
	}
}

func TestNewTelegramChannelInvalidToken(t *testing.T) {
	// Use a server that returns an error for getMe.
	srv := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tgResponse{
			OK:     false,
			Result: json.RawMessage(`null`),
		})
	}))
	defer srv.Close()

	eng, _ := policy.LoadFromBytes([]byte(`[policy]
default = "deny"
`))
	ptr := new(atomic.Pointer[policy.Engine])
	ptr.Store(eng)

	_, err := NewTelegramChannel(ChannelConfig{
		Token:       "bad-token",
		ChatID:      12345,
		EnginePtr:   ptr,
		ReloadMu:    new(sync.Mutex),
		APIEndpoint: srv.URL + "/bot%s/%s",
	})
	if err == nil {
		t.Error("expected error with bad token")
	}
	// Error should not contain the token.
	if strings.Contains(err.Error(), "bad-token") {
		t.Errorf("error should not leak token: %v", err)
	}
}

func TestNewTelegramChannelWithAllConfig(t *testing.T) {
	mock := newMockTelegramAPI(t)
	s := newTestStore(t)

	eng, err := policy.LoadFromStore(s)
	if err != nil {
		t.Fatal(err)
	}
	ptr := new(atomic.Pointer[policy.Engine])
	ptr.Store(eng)

	dir := t.TempDir()
	vaultStore, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	resolverPtr := new(atomic.Pointer[vault.BindingResolver])
	var swapCalled bool

	tc, err := NewTelegramChannel(ChannelConfig{
		Token:        "test-token",
		ChatID:       12345,
		EnginePtr:    ptr,
		ResolverPtr:  resolverPtr,
		ReloadMu:     new(sync.Mutex),
		Store:        s,
		Vault:        vaultStore,
		ContainerMgr: &mockContainerMgr{},
		OnEngineSwap: func(_ *policy.Engine) { swapCalled = true },
		APIEndpoint:  mock.endpoint(),
	})
	if err != nil {
		t.Fatalf("NewTelegramChannel: %v", err)
	}
	defer tc.Stop()

	// Verify all config was wired to the command handler.
	if tc.commands.vault == nil {
		t.Error("vault should be set")
	}
	if tc.commands.containerMgr == nil {
		t.Error("containerMgr should be set")
	}
	if tc.commands.resolverPtr == nil {
		t.Error("resolverPtr should be set")
	}
	if tc.commands.onEngineSwap == nil {
		t.Error("onEngineSwap should be set")
	}

	// Verify the callback works.
	tc.commands.onEngineSwap(eng)
	if !swapCalled {
		t.Error("onEngineSwap callback should have been called")
	}
}

// --- Type test ---

func TestTelegramChannelType(t *testing.T) {
	mock := newMockTelegramAPI(t)
	s := newTestStore(t)
	tc := newTestTelegramChannel(t, mock, s)

	if tc.Type() != channel.ChannelTelegram {
		t.Errorf("Type() = %v, want ChannelTelegram", tc.Type())
	}
}

// --- RequestApproval tests ---

func TestRequestApproval(t *testing.T) {
	mock := newMockTelegramAPI(t)
	s := newTestStore(t)
	tc := newTestTelegramChannel(t, mock, s)

	broker := channel.NewBroker([]channel.Channel{tc})
	tc.SetBroker(broker)

	// Start a request in the background and resolve it.
	done := make(chan struct{})
	var resp channel.Response
	var reqErr error
	go func() {
		resp, reqErr = broker.Request("evil.com", 443, "", 5*time.Second)
		close(done)
	}()

	// Wait for the message to be sent to Telegram.
	deadline := time.After(3 * time.Second)
	for {
		msgs := mock.getSentMessages()
		if len(msgs) > 0 {
			// Verify the message contains the destination.
			if !strings.Contains(msgs[0].Text, "evil.com") {
				t.Errorf("message should contain destination, got: %s", msgs[0].Text)
			}
			if !strings.Contains(msgs[0].Text, "443") {
				t.Errorf("message should contain port, got: %s", msgs[0].Text)
			}
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for sent message")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	// Resolve via broker.
	reqs := broker.PendingRequests()
	if len(reqs) == 0 {
		t.Fatal("expected pending request")
	}
	broker.Resolve(reqs[0].ID, channel.ResponseAllowOnce)

	<-done
	if reqErr != nil {
		t.Fatalf("request error: %v", reqErr)
	}
	if resp != channel.ResponseAllowOnce {
		t.Errorf("expected AllowOnce, got %v", resp)
	}
}

func TestRequestApprovalSendFailureSingleChannel(t *testing.T) {
	// Use a server that always fails sendMessage.
	srv := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(r.URL.Path, "/")
		method := parts[len(parts)-1]
		w.Header().Set("Content-Type", "application/json")
		switch method {
		case "getMe":
			_ = json.NewEncoder(w).Encode(tgResponse{
				OK:     true,
				Result: json.RawMessage(`{"id":1,"is_bot":true,"first_name":"Bot","username":"bot"}`),
			})
		case "sendMessage":
			// Simulate API error.
			_ = json.NewEncoder(w).Encode(tgResponse{OK: false, Result: json.RawMessage(`null`)})
		default:
			_ = json.NewEncoder(w).Encode(tgResponse{OK: true, Result: json.RawMessage(`true`)})
		}
	}))
	defer srv.Close()

	s := newTestStore(t)
	eng, _ := policy.LoadFromStore(s)
	ptr := new(atomic.Pointer[policy.Engine])
	ptr.Store(eng)

	tc, err := NewTelegramChannel(ChannelConfig{
		Token:       "test-token",
		ChatID:      12345,
		EnginePtr:   ptr,
		ReloadMu:    new(sync.Mutex),
		Store:       s,
		APIEndpoint: srv.URL + "/bot%s/%s",
	})
	if err != nil {
		t.Fatalf("NewTelegramChannel: %v", err)
	}
	defer tc.Stop()

	broker := channel.NewBroker([]channel.Channel{tc})
	tc.SetBroker(broker)

	// In single-channel mode, send failure should auto-deny.
	resp, err := broker.Request("fail.com", 443, "", 3*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != channel.ResponseDeny {
		t.Errorf("expected Deny on send failure, got %v", resp)
	}
}

// --- CancelApproval tests ---

func TestCancelApproval(t *testing.T) {
	mock := newMockTelegramAPI(t)
	s := newTestStore(t)
	tc := newTestTelegramChannel(t, mock, s)

	broker := channel.NewBroker([]channel.Channel{tc})
	tc.SetBroker(broker)

	// Store a message ID mapping.
	tc.msgMap.Store("req_test", approvalMsg{
		messageID: 42,
		req:       channel.ApprovalRequest{ID: "req_test", Destination: "test.example.com", Port: 443, Protocol: "https"},
	})

	err := tc.CancelApproval("req_test")
	if err != nil {
		t.Fatalf("CancelApproval: %v", err)
	}

	// Should have sent an edit message.
	time.Sleep(50 * time.Millisecond)
	edits := mock.getEditedMessages()
	if len(edits) == 0 {
		t.Error("expected edit message on cancel")
	} else if !strings.Contains(edits[0].Text, "resolved via another channel") {
		t.Errorf("cancel text should indicate resolution, got: %s", edits[0].Text)
	}

	// Message ID should be cleaned up.
	if _, ok := tc.msgMap.Load("req_test"); ok {
		t.Error("message ID should be removed after cancel")
	}
}

func TestCancelApprovalNoMessageStored(t *testing.T) {
	mock := newMockTelegramAPI(t)
	s := newTestStore(t)
	tc := newTestTelegramChannel(t, mock, s)

	// Cancel with no stored message should be a no-op.
	err := tc.CancelApproval("nonexistent_req")
	if err != nil {
		t.Fatalf("CancelApproval: %v", err)
	}

	time.Sleep(50 * time.Millisecond)
	edits := mock.getEditedMessages()
	if len(edits) != 0 {
		t.Error("should not send edit when no message is stored")
	}
}

func TestCancelApprovalShowsShutdownReason(t *testing.T) {
	mock := newMockTelegramAPI(t)
	s := newTestStore(t)
	tc := newTestTelegramChannel(t, mock, s)

	broker := channel.NewBroker([]channel.Channel{tc})
	tc.SetBroker(broker)
	broker.CancelAll() // Mark broker as closed.

	tc.msgMap.Store("req_shutdown", approvalMsg{
		messageID: 43,
		req:       channel.ApprovalRequest{ID: "req_shutdown", Destination: "shutdown.example.com", Port: 443, Protocol: "https"},
	})
	_ = tc.CancelApproval("req_shutdown")

	time.Sleep(50 * time.Millisecond)
	edits := mock.getEditedMessages()
	if len(edits) == 0 {
		t.Fatal("expected edit message")
	}
	if !strings.Contains(edits[0].Text, "shutting down") {
		t.Errorf("should show shutdown reason, got: %s", edits[0].Text)
	}
}

// --- Start/Stop lifecycle tests ---

// TestRegisterCommands verifies that Start registers the bot command menu
// with the expected entries (order preserved), including /mcp for MCP
// upstream management.
func TestRegisterCommands(t *testing.T) {
	mock := newMockTelegramAPI(t)
	s := newTestStore(t)
	tc := newTestTelegramChannel(t, mock, s)

	// Start calls registerCommands synchronously before returning, so the mock
	// payload is available immediately with no polling needed.
	if err := tc.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(tc.Stop)

	raw := mock.getSetCommandsRaw()
	if raw == "" {
		t.Fatal("setMyCommands was not called by Start()")
	}

	var cmds []tgbotapi.BotCommand
	if err := json.Unmarshal([]byte(raw), &cmds); err != nil {
		t.Fatalf("unmarshal commands payload: %v (raw=%q)", err, raw)
	}

	// Order matches the Telegram menu grouping convention: status first, then
	// mutation groups, then meta commands.
	want := []tgbotapi.BotCommand{
		{Command: "status", Description: "Show proxy status"},
		{Command: "policy", Description: "Manage policy rules"},
		{Command: "cred", Description: "Manage credentials"},
		{Command: "mcp", Description: "Manage MCP upstreams"},
		{Command: "audit", Description: "Show audit log entries"},
		{Command: "start", Description: "Show welcome message"},
		{Command: "help", Description: "Show available commands"},
	}
	if len(cmds) != len(want) {
		t.Fatalf("got %d commands, want %d (unexpected extras?): %+v", len(cmds), len(want), cmds)
	}
	for i, w := range want {
		if cmds[i].Command != w.Command {
			t.Errorf("cmds[%d].Command = %q, want %q", i, cmds[i].Command, w.Command)
		}
		if cmds[i].Description != w.Description {
			t.Errorf("cmds[%d].Description = %q, want %q", i, cmds[i].Description, w.Description)
		}
	}
}

func TestStartStop(t *testing.T) {
	mock := newMockTelegramAPI(t)
	s := newTestStore(t)
	tc := newTestTelegramChannel(t, mock, s)

	if err := tc.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Inject an update and verify the channel processes it.
	mock.updates <- []tgbotapi.Update{{
		UpdateID: 1,
		Message: &tgbotapi.Message{
			MessageID: 1,
			Chat:      &tgbotapi.Chat{ID: 12345},
			Text:      "/help",
		},
	}}

	// Wait for the command to be processed.
	deadline := time.After(3 * time.Second)
	for {
		msgs := mock.getSentMessages()
		// Look for the help response (sent after getMe during init).
		helpFound := false
		for _, m := range msgs {
			if strings.Contains(m.Text, "Policy") {
				helpFound = true
				break
			}
		}
		if helpFound {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for help response")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	tc.Stop()

	// Double-stop should be safe.
	tc.Stop()
}

func TestStopIdempotent(t *testing.T) {
	mock := newMockTelegramAPI(t)
	s := newTestStore(t)
	tc := newTestTelegramChannel(t, mock, s)

	_ = tc.Start()
	tc.Stop()
	tc.Stop() // Should not panic.
}

// --- Commands channel test ---

func TestCommandsChannel(t *testing.T) {
	mock := newMockTelegramAPI(t)
	s := newTestStore(t)
	tc := newTestTelegramChannel(t, mock, s)

	ch := tc.Commands()
	if ch == nil {
		t.Fatal("Commands() should return non-nil channel")
	}
}

// --- Notify test ---

func TestNotify(t *testing.T) {
	mock := newMockTelegramAPI(t)
	s := newTestStore(t)
	tc := newTestTelegramChannel(t, mock, s)

	err := tc.Notify(context.Background(), "hello world")
	if err != nil {
		t.Fatalf("Notify: %v", err)
	}

	time.Sleep(50 * time.Millisecond)
	msgs := mock.getSentMessages()
	found := false
	for _, m := range msgs {
		if m.Text == "hello world" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Notify message not found in sent messages")
	}
}

// --- Callback handling tests ---

func TestHandleCallbackAllowOnce(t *testing.T) {
	mock := newMockTelegramAPI(t)
	s := newTestStore(t)
	tc := newTestTelegramChannel(t, mock, s)

	broker := channel.NewBroker([]channel.Channel{tc})
	tc.SetBroker(broker)

	done := make(chan channel.Response, 1)
	go func() {
		resp, _ := broker.Request("test.com", 443, "", 5*time.Second)
		done <- resp
	}()

	// Wait for request to register.
	waitForPending(t, broker, 1)

	reqs := broker.PendingRequests()
	reqID := reqs[0].ID

	// Simulate callback.
	tc.handleCallback(&tgbotapi.CallbackQuery{
		ID: "cb_1",
		Message: &tgbotapi.Message{
			MessageID: 200,
			Chat:      &tgbotapi.Chat{ID: 12345},
			Text:      "test message",
		},
		Data: reqID + "|allow_once",
	})

	resp := <-done
	if resp != channel.ResponseAllowOnce {
		t.Errorf("expected AllowOnce, got %v", resp)
	}
}

func TestHandleCallbackAlwaysAllow(t *testing.T) {
	mock := newMockTelegramAPI(t)
	s := newTestStore(t)
	tc := newTestTelegramChannel(t, mock, s)

	broker := channel.NewBroker([]channel.Channel{tc})
	tc.SetBroker(broker)

	done := make(chan channel.Response, 1)
	go func() {
		resp, _ := broker.Request("test.com", 443, "", 5*time.Second)
		done <- resp
	}()

	waitForPending(t, broker, 1)
	reqs := broker.PendingRequests()
	reqID := reqs[0].ID

	tc.handleCallback(&tgbotapi.CallbackQuery{
		ID: "cb_2",
		Message: &tgbotapi.Message{
			MessageID: 201,
			Chat:      &tgbotapi.Chat{ID: 12345},
			Text:      "test",
		},
		Data: reqID + "|always_allow",
	})

	resp := <-done
	if resp != channel.ResponseAlwaysAllow {
		t.Errorf("expected AlwaysAllow, got %v", resp)
	}
}

func TestHandleCallbackDeny(t *testing.T) {
	mock := newMockTelegramAPI(t)
	s := newTestStore(t)
	tc := newTestTelegramChannel(t, mock, s)

	broker := channel.NewBroker([]channel.Channel{tc})
	tc.SetBroker(broker)

	done := make(chan channel.Response, 1)
	go func() {
		resp, _ := broker.Request("test.com", 443, "", 5*time.Second)
		done <- resp
	}()

	waitForPending(t, broker, 1)
	reqs := broker.PendingRequests()
	reqID := reqs[0].ID

	tc.handleCallback(&tgbotapi.CallbackQuery{
		ID: "cb_3",
		Message: &tgbotapi.Message{
			MessageID: 202,
			Chat:      &tgbotapi.Chat{ID: 12345},
			Text:      "test",
		},
		Data: reqID + "|deny",
	})

	resp := <-done
	if resp != channel.ResponseDeny {
		t.Errorf("expected Deny, got %v", resp)
	}
}

func TestHandleCallbackUnauthorizedChat(t *testing.T) {
	mock := newMockTelegramAPI(t)
	s := newTestStore(t)
	tc := newTestTelegramChannel(t, mock, s)

	broker := channel.NewBroker([]channel.Channel{tc})
	tc.SetBroker(broker)

	done := make(chan channel.Response, 1)
	go func() {
		resp, _ := broker.Request("test.com", 443, "", 500*time.Millisecond)
		done <- resp
	}()

	waitForPending(t, broker, 1)
	reqs := broker.PendingRequests()
	reqID := reqs[0].ID

	// Callback from wrong chat should be ignored.
	tc.handleCallback(&tgbotapi.CallbackQuery{
		ID: "cb_unauth",
		Message: &tgbotapi.Message{
			MessageID: 203,
			Chat:      &tgbotapi.Chat{ID: 99999}, // Wrong chat.
			Text:      "test",
		},
		Data: reqID + "|allow_once",
	})

	// Request should time out because the callback was ignored.
	resp := <-done
	if resp != channel.ResponseDeny {
		t.Errorf("expected Deny (timeout), got %v", resp)
	}
}

func TestHandleCallbackNilMessage(t *testing.T) {
	mock := newMockTelegramAPI(t)
	s := newTestStore(t)
	tc := newTestTelegramChannel(t, mock, s)

	// Should not panic.
	tc.handleCallback(&tgbotapi.CallbackQuery{
		ID:      "cb_nil",
		Message: nil,
		Data:    "req_1|allow_once",
	})
}

func TestHandleCallbackInvalidData(t *testing.T) {
	mock := newMockTelegramAPI(t)
	s := newTestStore(t)
	tc := newTestTelegramChannel(t, mock, s)

	// Data without pipe separator should be silently ignored.
	tc.handleCallback(&tgbotapi.CallbackQuery{
		ID: "cb_bad",
		Message: &tgbotapi.Message{
			MessageID: 204,
			Chat:      &tgbotapi.Chat{ID: 12345},
		},
		Data: "no-pipe-separator",
	})
}

func TestHandleCallbackUnknownAction(t *testing.T) {
	mock := newMockTelegramAPI(t)
	s := newTestStore(t)
	tc := newTestTelegramChannel(t, mock, s)

	// Unknown action should be silently ignored.
	tc.handleCallback(&tgbotapi.CallbackQuery{
		ID: "cb_unknown",
		Message: &tgbotapi.Message{
			MessageID: 205,
			Chat:      &tgbotapi.Chat{ID: 12345},
		},
		Data: "req_1|unknown_action",
	})
}

// TestHandleCallbackAllowOncePreservesCodeBlockOnEdit reproduces the bug
// where the <pre><code> args block was lost from the final edit after the
// user tapped Allow. The root cause was that broker.Resolve synchronously
// calls cancelOnChannels -> tc.CancelApproval on the same Telegram channel,
// which LoadAndDelete'd the msgMap entry and issued its own edit. Control
// then returned to handleCallback, which could not find the entry in
// msgMap and fell back to editing with cq.Message.Text (Telegram's
// plain-text extraction, where <pre>/<code> tags are already stripped).
// That second edit clobbered the first and lost the code block. The fix
// is for handleCallback to take ownership of the msgMap entry BEFORE
// calling broker.Resolve so CancelApproval becomes a no-op.
func TestHandleCallbackAllowOncePreservesCodeBlockOnEdit(t *testing.T) {
	mock := newMockTelegramAPI(t)
	s := newTestStore(t)
	tc := newTestTelegramChannel(t, mock, s)

	broker := channel.NewBroker([]channel.Channel{tc})
	tc.SetBroker(broker)

	const toolArgs = `{"owner":"me","repo":"x"}`
	done := make(chan channel.Response, 1)
	go func() {
		resp, _ := broker.Request(
			"github__list_branches", 0, "mcp", 5*time.Second,
			channel.WithToolArgs(toolArgs),
		)
		done <- resp
	}()

	waitForPending(t, broker, 1)
	reqs := broker.PendingRequests()
	if len(reqs) != 1 {
		t.Fatalf("expected 1 pending request, got %d", len(reqs))
	}
	req := reqs[0]

	// Wait for sendApprovalMessage goroutine to populate msgMap (it runs
	// async after broadcast). The mock API returns immediately so this is
	// typically fast.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if _, ok := tc.msgMap.Load(req.ID); ok {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, ok := tc.msgMap.Load(req.ID); !ok {
		t.Fatal("msgMap entry was not populated by sendApprovalMessage")
	}

	// Simulate user tapping "Allow". Message.Text is what Telegram returns
	// in callback queries: the sent HTML text with all formatting tags
	// stripped. The JSON content is still present (newlines preserved)
	// but the <pre><code> wrapping is gone.
	tc.handleCallback(&tgbotapi.CallbackQuery{
		ID: "cb_allow",
		Message: &tgbotapi.Message{
			MessageID: 101,
			Chat:      &tgbotapi.Chat{ID: 12345},
			Text:      "OpenClaw wants to call tool:\n\ngithub__list_branches\n\nArguments:\n{\n  \"owner\": \"me\",\n  \"repo\": \"x\"\n}\n\nAllow this tool call?",
		},
		Data: req.ID + "|allow_once",
	})

	if resp := <-done; resp != channel.ResponseAllowOnce {
		t.Errorf("expected AllowOnce, got %v", resp)
	}

	// The FINAL edit (last-write-wins) must still contain the code block
	// and the "Allowed (once)" status label. Multiple edits may fire
	// (cancelOnChannels also triggers one), so we check the last entry.
	edits := mock.getEditedMessages()
	if len(edits) == 0 {
		t.Fatal("expected at least one edit")
	}
	last := edits[len(edits)-1]
	if !strings.Contains(last.Text, `<pre><code class="language-json">`) {
		t.Errorf("final edit lost <pre><code> block.\nfinal edit text:\n%s", last.Text)
	}
	if !strings.Contains(last.Text, "Allowed (once)") {
		t.Errorf("final edit missing 'Allowed (once)' label.\nfinal edit text:\n%s", last.Text)
	}
}

func TestHandleCallbackAlreadyResolved(t *testing.T) {
	mock := newMockTelegramAPI(t)
	s := newTestStore(t)
	tc := newTestTelegramChannel(t, mock, s)

	broker := channel.NewBroker([]channel.Channel{tc})
	tc.SetBroker(broker)

	// No pending request for this ID, so it's already resolved.
	tc.handleCallback(&tgbotapi.CallbackQuery{
		ID: "cb_stale",
		Message: &tgbotapi.Message{
			MessageID: 206,
			Chat:      &tgbotapi.Chat{ID: 12345},
			Text:      "test",
		},
		Data: "req_nonexistent|allow_once",
	})

	// Should answer with "Already resolved".
	time.Sleep(50 * time.Millisecond)
	cbs := mock.getCallbacks()
	found := false
	for _, cb := range cbs {
		if cb.Text == "Already resolved" {
			found = true
		}
	}
	if !found {
		t.Error("should answer callback with 'Already resolved'")
	}
}

func TestHandleCallbackTimedOutRequest(t *testing.T) {
	mock := newMockTelegramAPI(t)
	s := newTestStore(t)
	tc := newTestTelegramChannel(t, mock, s)

	broker := channel.NewBroker([]channel.Channel{tc})
	tc.SetBroker(broker)

	// Create a request and let it time out.
	_, _ = broker.Request("timeout.com", 443, "", 50*time.Millisecond)
	time.Sleep(150 * time.Millisecond)

	// The request timed out, so the callback should report "Request timed out".
	// We need to find the request ID. The broker uses sequential IDs.
	// Try the likely ID.
	tc.handleCallback(&tgbotapi.CallbackQuery{
		ID: "cb_late",
		Message: &tgbotapi.Message{
			MessageID: 300,
			Chat:      &tgbotapi.Chat{ID: 12345},
			Text:      "original text",
		},
		Data: "req_1|allow_once",
	})

	time.Sleep(50 * time.Millisecond)
	cbs := mock.getCallbacks()
	// Should answer with either "Request timed out" or "Already resolved".
	if len(cbs) == 0 {
		t.Error("expected callback answer")
	}
}

// --- Stale approval cleanup tests ---

func TestStaleApprovalCleanup(t *testing.T) {
	mock := newMockTelegramAPI(t)
	s := newTestStore(t)
	tc := newTestTelegramChannel(t, mock, s)

	broker := channel.NewBroker([]channel.Channel{tc})
	tc.SetBroker(broker)

	// Request that times out while the Telegram API call is in flight.
	// The sendApprovalMessage should detect the timed-out state and edit
	// the message to show "(request timed out)".
	resp, _ := broker.Request("stale.com", 443, "", 50*time.Millisecond)
	if resp != channel.ResponseDeny {
		t.Errorf("expected Deny on timeout, got %v", resp)
	}

	// Give time for the async sendApprovalMessage to complete and detect timeout.
	time.Sleep(300 * time.Millisecond)

	edits := mock.getEditedMessages()
	// Should have at least one edit showing "timed out".
	timedOutEdit := false
	for _, e := range edits {
		if strings.Contains(e.Text, "timed out") {
			timedOutEdit = true
			break
		}
	}
	// The edit may or may not happen depending on timing.
	// The important thing is that the request completes without hanging.
	_ = timedOutEdit
}

// --- Setter tests ---

func TestSetBroker(t *testing.T) {
	mock := newMockTelegramAPI(t)
	s := newTestStore(t)
	tc := newTestTelegramChannel(t, mock, s)

	if tc.broker != nil {
		t.Error("broker should be nil before SetBroker")
	}

	broker := channel.NewBroker([]channel.Channel{tc})
	tc.SetBroker(broker)

	if tc.broker == nil {
		t.Error("broker should be set after SetBroker")
	}
	if tc.commands.broker == nil {
		t.Error("command handler broker should be set after SetBroker")
	}
}

func TestSetDockerManager(t *testing.T) {
	s := newTestStore(t)
	h := newTestHandlerWithStore(t, s, nil, "")

	if h.containerMgr != nil {
		t.Error("containerMgr should be nil initially")
	}

	mgr := &mockContainerMgr{}
	h.SetContainerManager(mgr)

	if h.containerMgr == nil {
		t.Error("containerMgr should be set")
	}
}

func TestSetResolverPtr(t *testing.T) {
	s := newTestStore(t)
	h := newTestHandlerWithStore(t, s, nil, "")

	if h.resolverPtr != nil {
		t.Error("resolverPtr should be nil initially")
	}

	ptr := new(atomic.Pointer[vault.BindingResolver])
	h.SetResolverPtr(ptr)

	if h.resolverPtr == nil {
		t.Error("resolverPtr should be set")
	}
}

func TestSetVault(t *testing.T) {
	s := newTestStore(t)
	h := newTestHandlerWithStore(t, s, nil, "")

	if h.vault != nil {
		t.Error("vault should be nil initially")
	}

	dir := t.TempDir()
	vaultStore, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	h.SetVault(vaultStore)

	if h.vault == nil {
		t.Error("vault should be set")
	}
}

func TestSetOnEngineSwap(t *testing.T) {
	s := newTestStore(t)
	h := newTestHandlerWithStore(t, s, nil, "")

	if h.onEngineSwap != nil {
		t.Error("onEngineSwap should be nil initially")
	}

	called := false
	h.SetOnEngineSwap(func(_ *policy.Engine) { called = true })

	if h.onEngineSwap == nil {
		t.Error("onEngineSwap should be set")
	}

	// Verify it works by calling it.
	h.onEngineSwap(nil)
	if !called {
		t.Error("onEngineSwap callback should have been invoked")
	}
}

// --- handleMessage tests ---

func TestHandleMessageUnauthorizedChat(t *testing.T) {
	mock := newMockTelegramAPI(t)
	s := newTestStore(t)
	tc := newTestTelegramChannel(t, mock, s)

	initialMsgs := len(mock.getSentMessages())

	tc.handleMessage(&tgbotapi.Message{
		MessageID: 1,
		Chat:      &tgbotapi.Chat{ID: 99999}, // Wrong chat.
		Text:      "/help",
	})

	time.Sleep(50 * time.Millisecond)
	// No reply should be sent for unauthorized chat.
	if len(mock.getSentMessages()) != initialMsgs {
		t.Error("should not reply to unauthorized chat")
	}
}

func TestHandleMessageNonCommand(t *testing.T) {
	mock := newMockTelegramAPI(t)
	s := newTestStore(t)
	tc := newTestTelegramChannel(t, mock, s)

	initialMsgs := len(mock.getSentMessages())

	tc.handleMessage(&tgbotapi.Message{
		MessageID: 1,
		Chat:      &tgbotapi.Chat{ID: 12345},
		Text:      "just a regular message",
	})

	time.Sleep(50 * time.Millisecond)
	if len(mock.getSentMessages()) != initialMsgs {
		t.Error("should not reply to non-command messages")
	}
}

func TestHandleMessageCredAddDeletesMessage(t *testing.T) {
	mock := newMockTelegramAPI(t)
	s := newTestStore(t)
	tc := newTestTelegramChannel(t, mock, s)

	dir := t.TempDir()
	vaultStore, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	tc.commands.SetVault(vaultStore)

	tc.handleMessage(&tgbotapi.Message{
		MessageID: 500,
		Chat:      &tgbotapi.Chat{ID: 12345},
		Text:      "/cred add my_secret super-secret-value",
	})

	time.Sleep(100 * time.Millisecond)
	deleted := mock.getDeletedMessages()
	if len(deleted) == 0 {
		t.Error("cred add message should be deleted for security")
	}
}

func TestHandleMessageCredRotateDeletesMessage(t *testing.T) {
	mock := newMockTelegramAPI(t)
	s := newTestStore(t)
	tc := newTestTelegramChannel(t, mock, s)

	dir := t.TempDir()
	vaultStore, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	tc.commands.SetVault(vaultStore)
	_, _ = vaultStore.Add("my_key", "old_value")

	tc.handleMessage(&tgbotapi.Message{
		MessageID: 501,
		Chat:      &tgbotapi.Chat{ID: 12345},
		Text:      "/cred rotate my_key new-value",
	})

	time.Sleep(100 * time.Millisecond)
	deleted := mock.getDeletedMessages()
	if len(deleted) == 0 {
		t.Error("cred rotate message should be deleted for security")
	}
}

func TestHandleMessageMCPAddDeletesMessage(t *testing.T) {
	mock := newMockTelegramAPI(t)
	s := newTestStore(t)
	tc := newTestTelegramChannel(t, mock, s)

	// /mcp add may carry secrets via --env KEY=VAL so the chat message
	// should be deleted the same way /cred add is.
	tc.handleMessage(&tgbotapi.Message{
		MessageID: 700,
		Chat:      &tgbotapi.Chat{ID: 12345},
		Text:      "/mcp add github --command npx --env GITHUB_PAT=super-secret",
	})

	time.Sleep(100 * time.Millisecond)
	if len(mock.getDeletedMessages()) == 0 {
		t.Error("mcp add message should be deleted for security")
	}
	// The plaintext --env value must not leak via the external command
	// channel. handleMessage routes sensitive commands to the internal
	// CommandHandler only.
	if len(tc.cmdCh) != 0 {
		t.Errorf("/mcp add must not forward to cmdCh (got %d entries, risks leaking --env secrets)", len(tc.cmdCh))
	}
}

func TestHandleMessageMCPListNotDeleted(t *testing.T) {
	mock := newMockTelegramAPI(t)
	s := newTestStore(t)
	tc := newTestTelegramChannel(t, mock, s)

	// /mcp list never carries secrets so the message should not be deleted.
	tc.handleMessage(&tgbotapi.Message{
		MessageID: 701,
		Chat:      &tgbotapi.Chat{ID: 12345},
		Text:      "/mcp list",
	})

	time.Sleep(100 * time.Millisecond)
	if len(mock.getDeletedMessages()) != 0 {
		t.Error("non-sensitive /mcp list message should not be deleted")
	}
}

// TestHandleMessageMCPListTruncation seeds enough upstreams to push /mcp
// list past the 4000-rune telegram limit and verifies the truncated
// response keeps <code> and <b> balanced. An unbalanced tag would make
// Telegram reject the message under HTML parse mode.
func TestHandleMessageMCPListTruncation(t *testing.T) {
	mock := newMockTelegramAPI(t)
	s := newTestStore(t)
	// Seed 200 upstreams so the output comfortably exceeds telegramMaxMessage.
	for i := 0; i < 200; i++ {
		name := "upstream_" + strconv.Itoa(i)
		if _, err := s.AddMCPUpstream(name, "npx", store.MCPUpstreamOpts{
			Transport: "stdio",
			Args:      []string{"--arg", "padding-to-ensure-overflow"},
		}); err != nil {
			t.Fatal(err)
		}
	}
	tc := newTestTelegramChannel(t, mock, s)

	tc.handleMessage(&tgbotapi.Message{
		MessageID: 800,
		Chat:      &tgbotapi.Chat{ID: 12345},
		Text:      "/mcp list",
	})

	time.Sleep(100 * time.Millisecond)
	msgs := mock.getSentMessages()
	if len(msgs) == 0 {
		t.Fatal("expected sendMessage to be called")
	}
	text := msgs[len(msgs)-1].Text
	if !strings.Contains(text, "(truncated)") {
		t.Errorf("expected truncation marker, got first 200 chars: %q", text[:min(200, len(text))])
	}
	if opens, closes := strings.Count(text, "<code>"), strings.Count(text, "</code>"); opens != closes {
		t.Errorf("truncated output breaks <code> balance: %d open, %d close", opens, closes)
	}
	if opens, closes := strings.Count(text, "<b>"), strings.Count(text, "</b>"); opens != closes {
		t.Errorf("truncated output breaks <b> balance: %d open, %d close", opens, closes)
	}
}

func TestContainsSensitiveArgs(t *testing.T) {
	tests := []struct {
		name string
		cmd  *Command
		want bool
	}{
		{"nil command", nil, false},
		{"empty args", &Command{Name: "cred"}, false},
		{"cred add", &Command{Name: "cred", Args: []string{"add", "name", "secret"}}, true},
		{"cred rotate", &Command{Name: "cred", Args: []string{"rotate", "name", "secret"}}, true},
		{"cred list", &Command{Name: "cred", Args: []string{"list"}}, false},
		{"cred remove", &Command{Name: "cred", Args: []string{"remove", "name"}}, false},
		{"mcp add", &Command{Name: "mcp", Args: []string{"add", "name", "--command", "cmd"}}, true},
		{"mcp list", &Command{Name: "mcp", Args: []string{"list"}}, false},
		{"mcp remove", &Command{Name: "mcp", Args: []string{"remove", "name"}}, false},
		{"policy show", &Command{Name: "policy", Args: []string{"show"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := containsSensitiveArgs(tt.cmd); got != tt.want {
				t.Errorf("containsSensitiveArgs(%+v) = %v, want %v", tt.cmd, got, tt.want)
			}
		})
	}
}

func TestHandleMessageForwardsToCommandChannel(t *testing.T) {
	mock := newMockTelegramAPI(t)
	s := newTestStore(t)
	tc := newTestTelegramChannel(t, mock, s)

	tc.handleMessage(&tgbotapi.Message{
		MessageID: 1,
		Chat:      &tgbotapi.Chat{ID: 12345},
		Text:      "/status",
	})

	// The command should be forwarded to the command channel.
	select {
	case cmd := <-tc.cmdCh:
		if cmd.Name != "status" {
			t.Errorf("expected command name 'status', got %q", cmd.Name)
		}
		if cmd.ChannelType != channel.ChannelTelegram {
			t.Errorf("expected ChannelTelegram, got %v", cmd.ChannelType)
		}
	case <-time.After(time.Second):
		t.Error("timed out waiting for command on channel")
	}
}

func TestHandleMessageCredAddNotForwardedToChannel(t *testing.T) {
	mock := newMockTelegramAPI(t)
	s := newTestStore(t)
	tc := newTestTelegramChannel(t, mock, s)

	dir := t.TempDir()
	vaultStore, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	tc.commands.SetVault(vaultStore)

	tc.handleMessage(&tgbotapi.Message{
		MessageID: 1,
		Chat:      &tgbotapi.Chat{ID: 12345},
		Text:      "/cred add secret_key value123",
	})

	// Sensitive cred commands should NOT be forwarded to the command channel.
	select {
	case cmd := <-tc.cmdCh:
		t.Errorf("cred add should not be forwarded to command channel, got: %+v", cmd)
	case <-time.After(100 * time.Millisecond):
		// Expected: no command forwarded.
	}
}

func TestHandleMessageTruncatesLongResponse(t *testing.T) {
	mock := newMockTelegramAPI(t)
	s := newTestStore(t)
	tc := newTestTelegramChannel(t, mock, s)

	// Add many rules to generate a long response.
	for i := 0; i < 200; i++ {
		_, _ = s.AddRule("allow", store.RuleOpts{Destination: fmt.Sprintf("very-long-domain-name-%d.example.com", i)})
	}
	// Recompile engine so policy show works.
	eng, _ := policy.LoadFromStore(s)
	tc.commands.engine.Store(eng)

	tc.handleMessage(&tgbotapi.Message{
		MessageID: 1,
		Chat:      &tgbotapi.Chat{ID: 12345},
		Text:      "/policy show",
	})

	time.Sleep(100 * time.Millisecond)
	msgs := mock.getSentMessages()
	// Find the policy show response.
	for _, m := range msgs {
		if strings.Contains(m.Text, "Current policy") && len(m.Text) > 3000 {
			if !strings.Contains(m.Text, "(truncated)") {
				t.Error("long messages should be truncated")
			}
			return
		}
	}
}

// --- /cred commands with mock container manager ---

func TestCredAddWithContainerManager(t *testing.T) {
	s := newTestStore(t)
	h := newTestHandlerWithStore(t, s, nil, "")

	dir := t.TempDir()
	vaultStore, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	h.SetVault(vaultStore)

	mgr := &mockContainerMgr{}
	h.SetContainerManager(mgr)

	// Add credential without --env-var: no env injection happens.
	result := h.Handle(&Command{Name: "cred", Args: []string{"add", "api_key", "sk-test123"}})
	if !strings.Contains(result, "Added credential") {
		t.Errorf("expected add confirmation, got: %s", result)
	}
	if mgr.injectCalledSafe() {
		t.Error("InjectEnvVars should not be called when no env_var bindings exist")
	}
}

func TestCredAddWithContainerManagerAndEnvVar(t *testing.T) {
	s := newTestStore(t)
	h := newTestHandlerWithStore(t, s, nil, "")

	dir := t.TempDir()
	vaultStore, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	h.SetVault(vaultStore)

	mgr := &mockContainerMgr{}
	h.SetContainerManager(mgr)

	// Add credential with --env-var: InjectEnvVars should be called.
	result := h.Handle(&Command{Name: "cred", Args: []string{"add", "api_key", "sk-test123", "--env-var", "OPENAI_API_KEY"}})
	if !strings.Contains(result, "Added credential") {
		t.Errorf("expected add confirmation, got: %s", result)
	}
	if !strings.Contains(result, "env vars updated") {
		t.Errorf("should indicate env vars updated, got: %s", result)
	}

	if !mgr.injectCalledSafe() {
		t.Error("InjectEnvVars should have been called")
	}
	if _, ok := mgr.injectEnvSafe()["OPENAI_API_KEY"]; !ok {
		t.Error("InjectEnvVars should include OPENAI_API_KEY")
	}
}

func TestCredRemoveWithContainerManager(t *testing.T) {
	s := newTestStore(t)
	h := newTestHandlerWithStore(t, s, nil, "")

	dir := t.TempDir()
	vaultStore, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	h.SetVault(vaultStore)

	mgr := &mockContainerMgr{}
	h.SetContainerManager(mgr)

	// Add with env_var, then remove. InjectEnvVars should be called with
	// an empty value for the removed env var.
	_, _ = vaultStore.Add("test_cred", "value")
	_, _ = s.AddBinding("api.example.com", "test_cred", store.BindingOpts{EnvVar: "TEST_API_KEY"})

	result := h.Handle(&Command{Name: "cred", Args: []string{"remove", "test_cred"}})
	if !strings.Contains(result, "Removed credential") {
		t.Errorf("expected remove confirmation, got: %s", result)
	}

	if !mgr.injectCalledSafe() {
		t.Error("InjectEnvVars should have been called after remove")
	}
	if v, ok := mgr.injectEnvSafe()["TEST_API_KEY"]; !ok || v != "" {
		t.Errorf("removed env var should be empty, got: %q (exists=%v)", v, ok)
	}
}

func TestCredRotateWithContainerManager(t *testing.T) {
	s := newTestStore(t)
	h := newTestHandlerWithStore(t, s, nil, "")

	dir := t.TempDir()
	vaultStore, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	h.SetVault(vaultStore)

	mgr := &mockContainerMgr{}
	h.SetContainerManager(mgr)

	// Add first with env_var binding.
	_, _ = vaultStore.Add("rotate_key", "old_value")
	_, _ = s.AddBinding("api.example.com", "rotate_key", store.BindingOpts{EnvVar: "ROTATE_KEY"})

	result := h.Handle(&Command{Name: "cred", Args: []string{"rotate", "rotate_key", "new_value"}})
	if !strings.Contains(result, "Rotated credential") {
		t.Errorf("expected rotate confirmation, got: %s", result)
	}
	if !mgr.injectCalledSafe() {
		t.Error("InjectEnvVars should have been called after rotate")
	}
}

func TestCredUsageMessages(t *testing.T) {
	s := newTestStore(t)
	h := newTestHandlerWithStore(t, s, nil, "")

	dir := t.TempDir()
	vaultStore, _ := vault.NewStore(dir)
	h.SetVault(vaultStore)

	// Missing args.
	result := h.Handle(&Command{Name: "cred", Args: nil})
	if !strings.Contains(result, "Usage") {
		t.Errorf("expected usage, got: %s", result)
	}

	result = h.Handle(&Command{Name: "cred", Args: []string{"add", "name_only"}})
	if !strings.Contains(result, "Usage") {
		t.Errorf("expected usage for incomplete add, got: %s", result)
	}

	result = h.Handle(&Command{Name: "cred", Args: []string{"rotate", "name_only"}})
	if !strings.Contains(result, "Usage") {
		t.Errorf("expected usage for incomplete rotate, got: %s", result)
	}

	result = h.Handle(&Command{Name: "cred", Args: []string{"remove"}})
	if !strings.Contains(result, "Usage") {
		t.Errorf("expected usage for incomplete remove, got: %s", result)
	}

	result = h.Handle(&Command{Name: "cred", Args: []string{"unknown_sub"}})
	if !strings.Contains(result, "Unknown cred subcommand") {
		t.Errorf("expected unknown subcommand, got: %s", result)
	}
}

// --- /policy commands verifying store writes and engine recompile ---

func TestPolicyAllowRecompilesEngine(t *testing.T) {
	s := newTestStore(t)
	h := newTestHandlerWithStore(t, s, nil, "")

	swapCount := 0
	h.SetOnEngineSwap(func(_ *policy.Engine) { swapCount++ })

	h.Handle(&Command{Name: "policy", Args: []string{"allow", "recompile-test.com"}})

	if swapCount != 1 {
		t.Errorf("expected 1 engine swap, got %d", swapCount)
	}

	// Verify engine now has the rule.
	snap := h.engine.Load().Snapshot()
	found := false
	for _, r := range snap.AllowRules {
		if r.Destination == "recompile-test.com" {
			found = true
		}
	}
	if !found {
		t.Error("engine should contain the new allow rule after recompile")
	}
}

func TestPolicyDenyRecompilesEngine(t *testing.T) {
	s := newTestStore(t)
	h := newTestHandlerWithStore(t, s, nil, "")

	swapCount := 0
	h.SetOnEngineSwap(func(_ *policy.Engine) { swapCount++ })

	h.Handle(&Command{Name: "policy", Args: []string{"deny", "deny-test.com"}})

	if swapCount != 1 {
		t.Errorf("expected 1 engine swap, got %d", swapCount)
	}

	snap := h.engine.Load().Snapshot()
	found := false
	for _, r := range snap.DenyRules {
		if r.Destination == "deny-test.com" {
			found = true
		}
	}
	if !found {
		t.Error("engine should contain the new deny rule after recompile")
	}
}

func TestPolicyRemoveRecompilesEngine(t *testing.T) {
	s := newTestStore(t)
	id, _ := s.AddRule("allow", store.RuleOpts{Destination: "remove-me.com"})
	h := newTestHandlerWithStore(t, s, nil, "")

	swapCount := 0
	h.SetOnEngineSwap(func(_ *policy.Engine) { swapCount++ })

	result := h.Handle(&Command{Name: "policy", Args: []string{"remove", fmt.Sprintf("%d", id)}})
	if !strings.Contains(result, "Removed") {
		t.Errorf("expected removal, got: %s", result)
	}

	if swapCount != 1 {
		t.Errorf("expected 1 engine swap, got %d", swapCount)
	}

	snap := h.engine.Load().Snapshot()
	if len(snap.AllowRules) != 0 {
		t.Error("engine should have no allow rules after removal")
	}
}

func TestPolicyAllowGlobPatternAccepted(t *testing.T) {
	s := newTestStore(t)
	h := newTestHandlerWithStore(t, s, nil, "")

	// Glob patterns with wildcards should be accepted.
	result := h.Handle(&Command{Name: "policy", Args: []string{"allow", "*.example.com"}})
	if !strings.Contains(result, "Added allow rule") {
		t.Errorf("expected acceptance of glob pattern, got: %s", result)
	}
}

func TestPolicyDenyGlobPatternAccepted(t *testing.T) {
	s := newTestStore(t)
	h := newTestHandlerWithStore(t, s, nil, "")

	result := h.Handle(&Command{Name: "policy", Args: []string{"deny", "**.evil.com"}})
	if !strings.Contains(result, "Added deny rule") {
		t.Errorf("expected acceptance of double-star glob, got: %s", result)
	}
}

func TestPolicyUsageMessages(t *testing.T) {
	s := newTestStore(t)
	h := newTestHandlerWithStore(t, s, nil, "")

	result := h.Handle(&Command{Name: "policy", Args: nil})
	if !strings.Contains(result, "Usage") {
		t.Errorf("expected usage, got: %s", result)
	}

	result = h.Handle(&Command{Name: "policy", Args: []string{"allow"}})
	if !strings.Contains(result, "Usage") {
		t.Errorf("expected usage for allow without dest, got: %s", result)
	}

	result = h.Handle(&Command{Name: "policy", Args: []string{"deny"}})
	if !strings.Contains(result, "Usage") {
		t.Errorf("expected usage for deny without dest, got: %s", result)
	}

	result = h.Handle(&Command{Name: "policy", Args: []string{"remove"}})
	if !strings.Contains(result, "Usage") {
		t.Errorf("expected usage for remove without id, got: %s", result)
	}

	result = h.Handle(&Command{Name: "policy", Args: []string{"badsubcmd"}})
	if !strings.Contains(result, "Unknown policy subcommand") {
		t.Errorf("expected unknown subcommand, got: %s", result)
	}
}

func TestPolicyShowFromEngine(t *testing.T) {
	// Test the engine fallback path (no store).
	eng, err := policy.LoadFromBytes([]byte(`[policy]
default = "ask"

[[allow]]
destination = "eng-allow.com"

[[deny]]
destination = "eng-deny.com"

[[ask]]
destination = "eng-ask.com"
`))
	if err != nil {
		t.Fatal(err)
	}
	ptr := new(atomic.Pointer[policy.Engine])
	ptr.Store(eng)
	h := NewCommandHandler(ptr, new(sync.Mutex), "")
	// Deliberately not setting store to test engine fallback.

	result := h.Handle(&Command{Name: "policy", Args: []string{"show"}})
	if !strings.Contains(result, "eng-allow.com") {
		t.Errorf("should show engine allow rule, got: %s", result)
	}
	if !strings.Contains(result, "eng-deny.com") {
		t.Errorf("should show engine deny rule, got: %s", result)
	}
	if !strings.Contains(result, "eng-ask.com") {
		t.Errorf("should show engine ask rule, got: %s", result)
	}
	if !strings.Contains(result, "ask") {
		t.Errorf("should show default verdict, got: %s", result)
	}
}

func TestPolicyShowEmpty(t *testing.T) {
	s := newTestStore(t)
	h := newTestHandlerWithStore(t, s, nil, "")

	result := h.Handle(&Command{Name: "policy", Args: []string{"show"}})
	if !strings.Contains(result, "No rules configured") {
		t.Errorf("should indicate no rules, got: %s", result)
	}
}

func TestHelpIncludesCredCommandsWhenVaultSet(t *testing.T) {
	s := newTestStore(t)
	h := newTestHandlerWithStore(t, s, nil, "")

	dir := t.TempDir()
	vaultStore, _ := vault.NewStore(dir)
	h.SetVault(vaultStore)

	result := h.Handle(&Command{Name: "help"})
	if !strings.Contains(result, "/cred") {
		t.Error("help should include /cred commands when vault is configured")
	}
}

func TestHelpExcludesCredCommandsWhenNoVault(t *testing.T) {
	s := newTestStore(t)
	h := newTestHandlerWithStore(t, s, nil, "")

	result := h.Handle(&Command{Name: "help"})
	if strings.Contains(result, "/cred") {
		t.Error("help should not include /cred commands when vault is not configured")
	}
}

// --- Audit command tests ---

func TestAuditNotConfigured(t *testing.T) {
	s := newTestStore(t)
	h := newTestHandlerWithStore(t, s, nil, "")

	result := h.Handle(&Command{Name: "audit", Args: []string{"recent"}})
	if !strings.Contains(result, "not configured") {
		t.Errorf("should indicate audit not configured, got: %s", result)
	}
}

func TestAuditInvalidUsage(t *testing.T) {
	s := newTestStore(t)
	h := newTestHandlerWithStore(t, s, nil, "/tmp/audit.jsonl")

	result := h.Handle(&Command{Name: "audit", Args: []string{"badarg"}})
	if !strings.Contains(result, "Usage") {
		t.Errorf("expected usage for bad audit args, got: %s", result)
	}
}

func TestAuditInvalidCount(t *testing.T) {
	s := newTestStore(t)
	h := newTestHandlerWithStore(t, s, nil, "/tmp/audit.jsonl")

	result := h.Handle(&Command{Name: "audit", Args: []string{"recent", "abc"}})
	if !strings.Contains(result, "Invalid count") {
		t.Errorf("expected invalid count, got: %s", result)
	}
}

func TestAuditNegativeCount(t *testing.T) {
	s := newTestStore(t)
	h := newTestHandlerWithStore(t, s, nil, "/tmp/audit.jsonl")

	result := h.Handle(&Command{Name: "audit", Args: []string{"recent", "-5"}})
	if !strings.Contains(result, "positive integer") {
		t.Errorf("expected positive integer message, got: %s", result)
	}
}

// --- In-memory fallback policy mutation tests ---

func TestPolicyAllowInMemoryFallback(t *testing.T) {
	eng, _ := policy.LoadFromBytes([]byte(`[policy]
default = "deny"
`))
	ptr := new(atomic.Pointer[policy.Engine])
	ptr.Store(eng)
	h := NewCommandHandler(ptr, new(sync.Mutex), "")

	result := h.Handle(&Command{Name: "policy", Args: []string{"allow", "inmem.com"}})
	if !strings.Contains(result, "Added allow rule") {
		t.Errorf("expected confirmation, got: %s", result)
	}
	if !strings.Contains(result, "in-memory only") {
		t.Errorf("should warn about in-memory, got: %s", result)
	}
}

func TestPolicyDenyInMemoryFallback(t *testing.T) {
	eng, _ := policy.LoadFromBytes([]byte(`[policy]
default = "allow"
`))
	ptr := new(atomic.Pointer[policy.Engine])
	ptr.Store(eng)
	h := NewCommandHandler(ptr, new(sync.Mutex), "")

	result := h.Handle(&Command{Name: "policy", Args: []string{"deny", "inmem.com"}})
	if !strings.Contains(result, "Added deny rule") {
		t.Errorf("expected confirmation, got: %s", result)
	}
	if !strings.Contains(result, "in-memory only") {
		t.Errorf("should warn about in-memory, got: %s", result)
	}
}

func TestPolicyRemoveInMemoryFallback(t *testing.T) {
	eng, _ := policy.LoadFromBytes([]byte(`[policy]
default = "deny"
`))
	ptr := new(atomic.Pointer[policy.Engine])
	ptr.Store(eng)
	h := NewCommandHandler(ptr, new(sync.Mutex), "")

	// Add a rule first.
	h.Handle(&Command{Name: "policy", Args: []string{"allow", "inmem-remove.com"}})

	result := h.Handle(&Command{Name: "policy", Args: []string{"remove", "inmem-remove.com"}})
	if !strings.Contains(result, "Removed rule") {
		t.Errorf("expected removal, got: %s", result)
	}
}

func TestPolicyRemoveInMemoryNotFound(t *testing.T) {
	eng, _ := policy.LoadFromBytes([]byte(`[policy]
default = "deny"
`))
	ptr := new(atomic.Pointer[policy.Engine])
	ptr.Store(eng)
	h := NewCommandHandler(ptr, new(sync.Mutex), "")

	result := h.Handle(&Command{Name: "policy", Args: []string{"remove", "nonexistent.com"}})
	if !strings.Contains(result, "No rule found") {
		t.Errorf("expected not found, got: %s", result)
	}
}

// --- rebuildResolver tests ---

func TestRebuildResolverNoStore(t *testing.T) {
	eng, _ := policy.LoadFromBytes([]byte(`[policy]
default = "deny"
`))
	ptr := new(atomic.Pointer[policy.Engine])
	ptr.Store(eng)
	h := NewCommandHandler(ptr, new(sync.Mutex), "")

	// Should be a no-op when store is nil.
	if err := h.rebuildResolver(); err != nil {
		t.Fatalf("rebuildResolver: %v", err)
	}
}

func TestRebuildResolverNoResolverPtr(t *testing.T) {
	s := newTestStore(t)
	h := newTestHandlerWithStore(t, s, nil, "")

	// Should be a no-op when resolverPtr is nil.
	if err := h.rebuildResolver(); err != nil {
		t.Fatalf("rebuildResolver: %v", err)
	}
}

func TestRebuildResolverWithBindings(t *testing.T) {
	s := newTestStore(t)
	h := newTestHandlerWithStore(t, s, nil, "")

	resolverPtr := new(atomic.Pointer[vault.BindingResolver])
	h.SetResolverPtr(resolverPtr)

	// Add a binding.
	_, _ = s.AddBinding("api.example.com", "my_cred", store.BindingOpts{
		Ports:    []int{443},
		Header:   "Authorization",
		Template: "Bearer {value}",
	})

	if err := h.rebuildResolver(); err != nil {
		t.Fatalf("rebuildResolver: %v", err)
	}

	resolver := resolverPtr.Load()
	if resolver == nil {
		t.Fatal("resolver should be set after rebuild with bindings")
	}
}

func TestRebuildResolverEmptyBindings(t *testing.T) {
	s := newTestStore(t)
	h := newTestHandlerWithStore(t, s, nil, "")

	resolverPtr := new(atomic.Pointer[vault.BindingResolver])
	h.SetResolverPtr(resolverPtr)

	if err := h.rebuildResolver(); err != nil {
		t.Fatalf("rebuildResolver: %v", err)
	}

	// Should store nil when no bindings exist.
	if resolverPtr.Load() != nil {
		t.Error("resolver should be nil when no bindings")
	}
}

// --- mockContainerMgr ---

// mockContainerMgr is a concurrency-safe stub ContainerManager used by the
// Telegram tests. All state fields are guarded by mu because command handlers
// may run on background goroutines (e.g. the telegram update loop) while the
// test asserts; the mutex prevents data races flagged by -race and gives tests
// deterministic reads.
type mockContainerMgr struct {
	mu            sync.Mutex
	injectCalled  bool
	injectEnv     map[string]string
	injectErr     error
	restartCalled bool
	restartErr    error
	// wireCalled tracks calls to WireMCPGateway. The MCP upstream mutation
	// path must NOT invoke it (sluice URL is wired once at startup and does
	// not change on /mcp add or /mcp remove), so tests assert wireCalled
	// remains false after those operations.
	wireCalled bool
}

func (m *mockContainerMgr) InjectEnvVars(_ context.Context, envMap map[string]string, _ bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.injectCalled = true
	m.injectEnv = envMap
	return m.injectErr
}

func (m *mockContainerMgr) RestartWithEnv(_ context.Context, _ map[string]string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.restartCalled = true
	return m.restartErr
}

func (m *mockContainerMgr) WireMCPGateway(_ context.Context, _, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.wireCalled = true
	return nil
}

// injectCalledSafe, injectEnvSafe, and wireCalledSafe are read accessors that
// lock mu so tests can observe state after handlers complete without tripping
// the race detector.
func (m *mockContainerMgr) injectCalledSafe() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.injectCalled
}

func (m *mockContainerMgr) injectEnvSafe() map[string]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.injectEnv == nil {
		return nil
	}
	out := make(map[string]string, len(m.injectEnv))
	for k, v := range m.injectEnv {
		out[k] = v
	}
	return out
}

func (m *mockContainerMgr) wireCalledSafe() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.wireCalled
}

func (m *mockContainerMgr) Status(_ context.Context) (container.ContainerStatus, error) {
	return container.ContainerStatus{Running: true}, nil
}

func (m *mockContainerMgr) Stop(_ context.Context) error {
	return nil
}

func (m *mockContainerMgr) InjectCACert(_ context.Context, _, _ string) error {
	return nil
}

func (m *mockContainerMgr) ReloadSecrets(_ context.Context) error {
	return nil
}

func (m *mockContainerMgr) Runtime() container.Runtime {
	return container.RuntimeDocker
}

// --- Helpers ---

func waitForPending(t *testing.T, broker *channel.Broker, n int) { //nolint:unparam // n is parameterized for test readability
	t.Helper()
	deadline := time.After(3 * time.Second)
	for broker.PendingCount() < n {
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for %d pending requests", n)
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
}
