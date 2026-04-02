package docker

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// mockClient implements ContainerClient for testing.
type mockClient struct {
	state       ContainerState
	inspectErr  error
	stopErr     error
	removeErr   error
	createErr   error
	startErr    error
	createdID   string
	createdSpec ContainerSpec
	stopped     bool
	removed     bool
	started     bool
}

func (m *mockClient) InspectContainer(_ context.Context, _ string) (ContainerState, error) {
	return m.state, m.inspectErr
}

func (m *mockClient) StopContainer(_ context.Context, _ string, _ int) error {
	m.stopped = true
	return m.stopErr
}

func (m *mockClient) RemoveContainer(_ context.Context, _ string) error {
	m.removed = true
	return m.removeErr
}

func (m *mockClient) CreateContainer(_ context.Context, spec ContainerSpec) (string, error) {
	m.createdSpec = spec
	return m.createdID, m.createErr
}

func (m *mockClient) StartContainer(_ context.Context, _ string) error {
	m.started = true
	return m.startErr
}

func TestRestartWithEnv(t *testing.T) {
	mc := &mockClient{
		state: ContainerState{
			ID:    "abc123",
			Image: "openclaw/openclaw:latest",
			Env:   []string{"EXISTING=value", "ANTHROPIC_API_KEY=old-phantom"},
		},
		createdID: "def456",
	}

	mgr := NewManager(mc, "openclaw")
	err := mgr.RestartWithEnv(context.Background(), map[string]string{
		"ANTHROPIC_API_KEY": "sk-ant-phantom-newvalue",
		"NEW_VAR":           "new-value",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !mc.stopped {
		t.Error("container should have been stopped")
	}
	if !mc.removed {
		t.Error("container should have been removed")
	}
	if !mc.started {
		t.Error("new container should have been started")
	}

	envMap := make(map[string]string)
	for _, e := range mc.createdSpec.Env {
		k, v, _ := strings.Cut(e, "=")
		envMap[k] = v
	}
	if envMap["EXISTING"] != "value" {
		t.Error("existing env var should be preserved")
	}
	if envMap["ANTHROPIC_API_KEY"] != "sk-ant-phantom-newvalue" {
		t.Errorf("updated env var wrong: %s", envMap["ANTHROPIC_API_KEY"])
	}
	if envMap["NEW_VAR"] != "new-value" {
		t.Error("new env var should be added")
	}
	if mc.createdSpec.Image != "openclaw/openclaw:latest" {
		t.Errorf("image should be preserved: %s", mc.createdSpec.Image)
	}
}

func TestRestartWithEnvInspectError(t *testing.T) {
	mc := &mockClient{
		inspectErr: fmt.Errorf("container not found"),
	}
	mgr := NewManager(mc, "openclaw")
	err := mgr.RestartWithEnv(context.Background(), map[string]string{"A": "1"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "inspect container") {
		t.Errorf("error should mention inspect: %v", err)
	}
}

func TestRestartWithEnvStopError(t *testing.T) {
	mc := &mockClient{
		state:   ContainerState{ID: "abc", Image: "test"},
		stopErr: fmt.Errorf("timeout"),
	}
	mgr := NewManager(mc, "openclaw")
	err := mgr.RestartWithEnv(context.Background(), map[string]string{"A": "1"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "stop container") {
		t.Errorf("error should mention stop: %v", err)
	}
}

func TestRestartWithEnvRemoveError(t *testing.T) {
	mc := &mockClient{
		state:     ContainerState{ID: "abc", Image: "test"},
		removeErr: fmt.Errorf("in use"),
	}
	mgr := NewManager(mc, "openclaw")
	err := mgr.RestartWithEnv(context.Background(), map[string]string{"A": "1"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "remove container") {
		t.Errorf("error should mention remove: %v", err)
	}
}

func TestRestartWithEnvCreateError(t *testing.T) {
	mc := &mockClient{
		state:     ContainerState{ID: "abc", Image: "test"},
		createErr: fmt.Errorf("image not found"),
	}
	mgr := NewManager(mc, "openclaw")
	err := mgr.RestartWithEnv(context.Background(), map[string]string{"A": "1"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "create container") {
		t.Errorf("error should mention create: %v", err)
	}
}

func TestRestartWithEnvStartError(t *testing.T) {
	mc := &mockClient{
		state:     ContainerState{ID: "abc", Image: "test"},
		createdID: "new123",
		startErr:  fmt.Errorf("port conflict"),
	}
	mgr := NewManager(mc, "openclaw")
	err := mgr.RestartWithEnv(context.Background(), map[string]string{"A": "1"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "start container") {
		t.Errorf("error should mention start: %v", err)
	}
}

func TestStatus(t *testing.T) {
	mc := &mockClient{
		state: ContainerState{
			ID:      "abc123",
			Image:   "openclaw/openclaw:latest",
			Running: true,
		},
	}

	mgr := NewManager(mc, "openclaw")
	status, err := mgr.Status(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.ID != "abc123" {
		t.Errorf("wrong ID: %s", status.ID)
	}
	if !status.Running {
		t.Error("should be running")
	}
	if status.Image != "openclaw/openclaw:latest" {
		t.Errorf("wrong image: %s", status.Image)
	}
}

func TestStop(t *testing.T) {
	mc := &mockClient{}
	mgr := NewManager(mc, "openclaw")
	err := mgr.Stop(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !mc.stopped {
		t.Error("container should have been stopped")
	}
}

func TestGeneratePhantomToken(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
	}{
		{"anthropic_api_key", "sk-ant-phantom-"},
		{"openai_api_key", "sk-phantom-"},
		{"github_token", "ghp_phantom"},
		{"unknown_cred", "phantom-"},
	}

	for _, tt := range tests {
		token := GeneratePhantomToken(tt.name)
		if !strings.HasPrefix(token, tt.prefix) {
			t.Errorf("GeneratePhantomToken(%q) = %q, want prefix %q", tt.name, token, tt.prefix)
		}
		if len(token) < len(tt.prefix)+10 {
			t.Errorf("GeneratePhantomToken(%q) too short: %q", tt.name, token)
		}
	}

	// Verify uniqueness across calls.
	t1 := GeneratePhantomToken("anthropic_api_key")
	t2 := GeneratePhantomToken("anthropic_api_key")
	if t1 == t2 {
		t.Error("phantom tokens should be unique across calls")
	}
}

func TestPhantomTokenFormatMatching(t *testing.T) {
	// Anthropic tokens start with sk-ant-
	token := GeneratePhantomToken("anthropic_api_key")
	if !strings.HasPrefix(token, "sk-ant-phantom-") {
		t.Errorf("anthropic phantom should start with sk-ant-phantom-: %s", token)
	}

	// OpenAI tokens start with sk-
	token = GeneratePhantomToken("openai_api_key")
	if !strings.HasPrefix(token, "sk-phantom-") {
		t.Errorf("openai phantom should start with sk-phantom-: %s", token)
	}

	// GitHub tokens start with ghp_
	token = GeneratePhantomToken("github_token")
	if !strings.HasPrefix(token, "ghp_phantom") {
		t.Errorf("github phantom should start with ghp_phantom: %s", token)
	}
}

func TestGeneratePhantomEnv(t *testing.T) {
	env := GeneratePhantomEnv([]string{"anthropic_api_key", "github_token"})

	if _, ok := env["ANTHROPIC_API_KEY"]; !ok {
		t.Error("should have ANTHROPIC_API_KEY")
	}
	if _, ok := env["GITHUB_TOKEN"]; !ok {
		t.Error("should have GITHUB_TOKEN")
	}
	if !strings.HasPrefix(env["ANTHROPIC_API_KEY"], "sk-ant-phantom-") {
		t.Errorf("ANTHROPIC_API_KEY should match format: %s", env["ANTHROPIC_API_KEY"])
	}
	if !strings.HasPrefix(env["GITHUB_TOKEN"], "ghp_phantom") {
		t.Errorf("GITHUB_TOKEN should match format: %s", env["GITHUB_TOKEN"])
	}
}

func TestCredNameToEnvVar(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"anthropic_api_key", "ANTHROPIC_API_KEY"},
		{"github_token", "GITHUB_TOKEN"},
		{"my_secret", "MY_SECRET"},
	}
	for _, tt := range tests {
		got := CredNameToEnvVar(tt.name)
		if got != tt.want {
			t.Errorf("CredNameToEnvVar(%q) = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestMergeEnv(t *testing.T) {
	existing := []string{"A=1", "B=2", "C=3"}
	updates := map[string]string{"B": "new2", "D": "4"}
	result := mergeEnv(existing, updates)

	envMap := make(map[string]string)
	for _, e := range result {
		k, v, _ := strings.Cut(e, "=")
		envMap[k] = v
	}

	if envMap["A"] != "1" {
		t.Error("A should be preserved")
	}
	if envMap["B"] != "new2" {
		t.Error("B should be updated")
	}
	if envMap["C"] != "3" {
		t.Error("C should be preserved")
	}
	if envMap["D"] != "4" {
		t.Error("D should be added")
	}
	if len(result) != 4 {
		t.Errorf("expected 4 entries, got %d", len(result))
	}
}

func TestMergeEnvPreservesOrder(t *testing.T) {
	existing := []string{"Z=1", "A=2", "M=3"}
	updates := map[string]string{"A": "updated"}
	result := mergeEnv(existing, updates)

	// Verify existing order is preserved.
	if result[0] != "Z=1" {
		t.Errorf("first entry should be Z=1, got %s", result[0])
	}
	if result[1] != "A=updated" {
		t.Errorf("second entry should be A=updated, got %s", result[1])
	}
	if result[2] != "M=3" {
		t.Errorf("third entry should be M=3, got %s", result[2])
	}
}

func TestMergeEnvEmpty(t *testing.T) {
	result := mergeEnv(nil, map[string]string{"A": "1"})
	if len(result) != 1 || result[0] != "A=1" {
		t.Errorf("expected [A=1], got %v", result)
	}

	result = mergeEnv([]string{"A=1"}, nil)
	if len(result) != 1 || result[0] != "A=1" {
		t.Errorf("expected [A=1], got %v", result)
	}

	result = mergeEnv(nil, nil)
	if len(result) != 0 {
		t.Errorf("expected empty, got %v", result)
	}
}
