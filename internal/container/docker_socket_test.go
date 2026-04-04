package container

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newTestServer creates a Unix socket HTTP server for testing.
// Returns the SocketClient, a mux to register handlers, and a cleanup function.
// Uses /tmp directly to keep the socket path short (macOS limits to 104 bytes).
func newTestServer(t *testing.T) (*SocketClient, *http.ServeMux, func()) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "sluice-test-")
	if err != nil {
		t.Fatalf("mkdirtemp: %v", err)
	}
	sock := filepath.Join(dir, "d.sock")

	mux := http.NewServeMux()
	listener, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}

	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(listener) }()

	client := NewSocketClient(sock)
	return client, mux, func() {
		_ = srv.Close()
		_ = os.RemoveAll(dir)
	}
}

func TestSocketClientInspect(t *testing.T) {
	client, mux, cleanup := newTestServer(t)
	defer cleanup()

	mux.HandleFunc("/v1.25/containers/testcontainer/json", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "want GET", http.StatusMethodNotAllowed)
			return
		}
		resp := map[string]interface{}{
			"Id": "abc123def",
			"State": map[string]interface{}{
				"Running": true,
			},
			"Config": map[string]interface{}{
				"Image":      "openclaw/openclaw:latest",
				"Env":        []string{"KEY=value", "OTHER=val2"},
				"Cmd":        []string{"--model", "claude"},
				"Entrypoint": []string{"/usr/bin/openclaw"},
			},
			"HostConfig": map[string]interface{}{
				"Binds":       []string{"openclaw-data:/root/.openclaw", "sluice-ca:/certs:ro"},
				"NetworkMode": "container:tun2proxy123",
			},
			"Mounts": []map[string]interface{}{
				{"Type": "volume", "Name": "openclaw-data", "Source": "/var/lib/docker/volumes/openclaw-data/_data", "Destination": "/root/.openclaw", "RW": true},
				{"Type": "volume", "Name": "sluice-ca", "Source": "/var/lib/docker/volumes/sluice-ca/_data", "Destination": "/certs", "RW": false},
			},
			"NetworkSettings": map[string]interface{}{
				"Networks": map[string]interface{}{
					"internal": map[string]interface{}{},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	state, err := client.InspectContainer(context.Background(), "testcontainer")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if state.ID != "abc123def" {
		t.Errorf("ID = %q, want abc123def", state.ID)
	}
	if state.Image != "openclaw/openclaw:latest" {
		t.Errorf("Image = %q, want openclaw/openclaw:latest", state.Image)
	}
	if !state.Running {
		t.Error("Running should be true")
	}
	if len(state.Env) != 2 || state.Env[0] != "KEY=value" {
		t.Errorf("Env = %v, want [KEY=value OTHER=val2]", state.Env)
	}
	if len(state.Cmd) != 2 || state.Cmd[0] != "--model" {
		t.Errorf("Cmd = %v, want [--model claude]", state.Cmd)
	}
	if len(state.Entrypoint) != 1 || state.Entrypoint[0] != "/usr/bin/openclaw" {
		t.Errorf("Entrypoint = %v, want [/usr/bin/openclaw]", state.Entrypoint)
	}
	if state.NetworkMode != "container:tun2proxy123" {
		t.Errorf("NetworkMode = %q, want container:tun2proxy123", state.NetworkMode)
	}
	if len(state.Binds) != 2 || state.Binds[0] != "openclaw-data:/root/.openclaw" {
		t.Errorf("Binds = %v, want [openclaw-data:/root/.openclaw sluice-ca:/certs:ro]", state.Binds)
	}
	if len(state.Mounts) != 2 {
		t.Fatalf("Mounts len = %d, want 2", len(state.Mounts))
	}
	if state.Mounts[0].Name != "openclaw-data" {
		t.Errorf("first mount Name = %q, want openclaw-data", state.Mounts[0].Name)
	}
	if state.Mounts[0].ReadOnly {
		t.Error("first mount should not be read-only (RW=true)")
	}
	if state.Mounts[1].Name != "sluice-ca" {
		t.Errorf("second mount Name = %q, want sluice-ca", state.Mounts[1].Name)
	}
	if !state.Mounts[1].ReadOnly {
		t.Error("second mount should be read-only (RW=false)")
	}
	if len(state.Networks) != 1 || state.Networks[0] != "internal" {
		t.Errorf("Networks = %v, want [internal]", state.Networks)
	}
}

func TestSocketClientInspectNotFound(t *testing.T) {
	client, mux, cleanup := newTestServer(t)
	defer cleanup()

	mux.HandleFunc("/v1.25/containers/missing/json", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "No such container"})
	})

	_, err := client.InspectContainer(context.Background(), "missing")
	if err == nil {
		t.Fatal("expected error for missing container")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should mention not found: %v", err)
	}
}

func TestSocketClientStop(t *testing.T) {
	client, mux, cleanup := newTestServer(t)
	defer cleanup()

	var gotPath string
	mux.HandleFunc("/v1.25/containers/mycontainer/stop", func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.RawQuery
		w.WriteHeader(http.StatusNoContent)
	})

	err := client.StopContainer(context.Background(), "mycontainer", 15)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotPath != "t=15" {
		t.Errorf("query = %q, want t=15", gotPath)
	}
}

func TestSocketClientStopAlreadyStopped(t *testing.T) {
	client, mux, cleanup := newTestServer(t)
	defer cleanup()

	mux.HandleFunc("/v1.25/containers/mycontainer/stop", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotModified)
	})

	err := client.StopContainer(context.Background(), "mycontainer", 10)
	if err != nil {
		t.Fatalf("304 should not be an error: %v", err)
	}
}

func TestSocketClientRemove(t *testing.T) {
	client, mux, cleanup := newTestServer(t)
	defer cleanup()

	var gotMethod string
	mux.HandleFunc("/v1.25/containers/mycontainer", func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		w.WriteHeader(http.StatusNoContent)
	})

	err := client.RemoveContainer(context.Background(), "mycontainer")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotMethod != "DELETE" {
		t.Errorf("method = %q, want DELETE", gotMethod)
	}
}

func TestSocketClientCreate(t *testing.T) {
	client, mux, cleanup := newTestServer(t)
	defer cleanup()

	var gotBody createRequest
	var gotName string
	mux.HandleFunc("/v1.25/containers/create", func(w http.ResponseWriter, r *http.Request) {
		gotName = r.URL.Query().Get("name")
		data, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(data, &gotBody)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"Id": "newcontainer789"})
	})

	id, err := client.CreateContainer(context.Background(), ContainerSpec{
		Name:        "openclaw",
		Image:       "openclaw/openclaw:latest",
		Env:         []string{"KEY=value"},
		Cmd:         []string{"--model", "claude"},
		Entrypoint:  []string{"/usr/bin/openclaw"},
		Binds:       []string{"data:/root/.openclaw", "ca:/certs:ro"},
		NetworkMode: "container:tun2proxy123",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if id != "newcontainer789" {
		t.Errorf("ID = %q, want newcontainer789", id)
	}
	if gotName != "openclaw" {
		t.Errorf("name = %q, want openclaw", gotName)
	}
	if gotBody.Image != "openclaw/openclaw:latest" {
		t.Errorf("Image = %q, want openclaw/openclaw:latest", gotBody.Image)
	}
	if len(gotBody.Env) != 1 || gotBody.Env[0] != "KEY=value" {
		t.Errorf("Env = %v, want [KEY=value]", gotBody.Env)
	}
	if len(gotBody.HostConfig.Binds) != 2 || gotBody.HostConfig.Binds[0] != "data:/root/.openclaw" {
		t.Errorf("Binds = %v, want [data:/root/.openclaw ca:/certs:ro]", gotBody.HostConfig.Binds)
	}
	if gotBody.HostConfig.NetworkMode != "container:tun2proxy123" {
		t.Errorf("NetworkMode = %q, want container:tun2proxy123", gotBody.HostConfig.NetworkMode)
	}
}

func TestSocketClientCreateVolumeMountUsesName(t *testing.T) {
	client, mux, cleanup := newTestServer(t)
	defer cleanup()

	var gotBody createRequest
	mux.HandleFunc("/v1.25/containers/create", func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(data, &gotBody)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"Id": "vol123"})
	})

	// Simulate a container with volume mounts that have no corresponding Binds.
	// This happens when containers are created with --mount type=volume syntax.
	_, err := client.CreateContainer(context.Background(), ContainerSpec{
		Name:  "testapp",
		Image: "app:latest",
		Mounts: []Mount{
			{Type: "volume", Name: "mydata", Source: "/var/lib/docker/volumes/mydata/_data", Destination: "/data"},
			{Type: "bind", Source: "/host/config", Destination: "/config", ReadOnly: true},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(gotBody.HostConfig.Mounts) != 2 {
		t.Fatalf("expected 2 mounts, got %d", len(gotBody.HostConfig.Mounts))
	}
	// Volume mount should use the volume Name, not the host path.
	if gotBody.HostConfig.Mounts[0].Source != "mydata" {
		t.Errorf("volume mount Source = %q, want %q (volume name)", gotBody.HostConfig.Mounts[0].Source, "mydata")
	}
	if gotBody.HostConfig.Mounts[0].Type != "volume" {
		t.Errorf("volume mount Type = %q, want volume", gotBody.HostConfig.Mounts[0].Type)
	}
	// Bind mount should keep its original Source path.
	if gotBody.HostConfig.Mounts[1].Source != "/host/config" {
		t.Errorf("bind mount Source = %q, want /host/config", gotBody.HostConfig.Mounts[1].Source)
	}
	if !gotBody.HostConfig.Mounts[1].ReadOnly {
		t.Error("bind mount should be read-only")
	}
}

func TestSocketClientStart(t *testing.T) {
	client, mux, cleanup := newTestServer(t)
	defer cleanup()

	var gotMethod string
	mux.HandleFunc("/v1.25/containers/newcontainer789/start", func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		w.WriteHeader(http.StatusNoContent)
	})

	err := client.StartContainer(context.Background(), "newcontainer789")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotMethod != "POST" {
		t.Errorf("method = %q, want POST", gotMethod)
	}
}

func TestSocketClientExecInContainer(t *testing.T) {
	client, mux, cleanup := newTestServer(t)
	defer cleanup()

	var execCreateBody execCreateRequest
	mux.HandleFunc("/v1.25/containers/mycontainer/exec", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "want POST", http.StatusMethodNotAllowed)
			return
		}
		data, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(data, &execCreateBody)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"Id": "exec123"})
	})

	mux.HandleFunc("/v1.25/exec/exec123/start", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "want POST", http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("/v1.25/exec/exec123/json", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"ExitCode": 0})
	})

	err := client.ExecInContainer(context.Background(), "mycontainer", []string{"openclaw", "secrets", "reload"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(execCreateBody.Cmd) != 3 || execCreateBody.Cmd[0] != "openclaw" {
		t.Errorf("exec Cmd = %v, want [openclaw secrets reload]", execCreateBody.Cmd)
	}
}

func TestSocketClientExecNonZeroExit(t *testing.T) {
	client, mux, cleanup := newTestServer(t)
	defer cleanup()

	mux.HandleFunc("/v1.25/containers/mycontainer/exec", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"Id": "exec456"})
	})

	mux.HandleFunc("/v1.25/exec/exec456/start", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("/v1.25/exec/exec456/json", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"ExitCode": 127})
	})

	err := client.ExecInContainer(context.Background(), "mycontainer", []string{"openclaw", "secrets", "reload"})
	if err == nil {
		t.Fatal("expected error for non-zero exit code")
	}
	if !strings.Contains(err.Error(), "127") {
		t.Errorf("error should mention exit code: %v", err)
	}
}

func TestSocketClientAPIError(t *testing.T) {
	client, mux, cleanup := newTestServer(t)
	defer cleanup()

	mux.HandleFunc("/v1.25/containers/bad/stop", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "something went wrong"})
	})

	err := client.StopContainer(context.Background(), "bad", 10)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "something went wrong") {
		t.Errorf("error should contain message: %v", err)
	}
}
