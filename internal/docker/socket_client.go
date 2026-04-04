package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// dockerAPIVersion is the minimum Docker Engine API version required.
// v1.25 (Docker 1.13+) supports all operations used here.
const dockerAPIVersion = "v1.25"

// SocketClient implements ContainerClient using the Docker Engine API
// over a Unix socket. It uses only stdlib net/http with no Docker SDK
// dependency.
type SocketClient struct {
	client *http.Client
}

// NewSocketClient creates a ContainerClient that communicates with Docker
// over the given Unix socket path (typically /var/run/docker.sock).
func NewSocketClient(socketPath string) *SocketClient {
	return &SocketClient{
		client: &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", socketPath)
				},
			},
		},
	}
}

func (c *SocketClient) apiURL(path string) string {
	return "http://localhost/" + dockerAPIVersion + path
}

func (c *SocketClient) InspectContainer(ctx context.Context, name string) (ContainerState, error) {
	resp, err := c.doRequest(ctx, "GET", "/containers/"+url.PathEscape(name)+"/json", nil)
	if err != nil {
		return ContainerState{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return ContainerState{}, fmt.Errorf("container %q not found", name)
	}
	if resp.StatusCode != http.StatusOK {
		return ContainerState{}, apiError(resp)
	}

	var ir inspectResponse
	if err := json.NewDecoder(resp.Body).Decode(&ir); err != nil {
		return ContainerState{}, fmt.Errorf("decode inspect response: %w", err)
	}

	mounts := make([]Mount, len(ir.Mounts))
	for i, m := range ir.Mounts {
		mounts[i] = Mount{
			Type:        m.Type,
			Name:        m.Name,
			Source:      m.Source,
			Destination: m.Destination,
			ReadOnly:    !m.RW,
		}
	}

	networks := make([]string, 0, len(ir.NetworkSettings.Networks))
	for name := range ir.NetworkSettings.Networks {
		networks = append(networks, name)
	}

	return ContainerState{
		ID:          ir.ID,
		Image:       ir.Config.Image,
		Env:         ir.Config.Env,
		Running:     ir.State.Running,
		Mounts:      mounts,
		Binds:       ir.HostConfig.Binds,
		Networks:    networks,
		NetworkMode: ir.HostConfig.NetworkMode,
		Cmd:         ir.Config.Cmd,
		Entrypoint:  ir.Config.Entrypoint,
	}, nil
}

func (c *SocketClient) StopContainer(ctx context.Context, name string, timeoutSec int) error {
	resp, err := c.doRequest(ctx, "POST",
		"/containers/"+url.PathEscape(name)+"/stop?t="+strconv.Itoa(timeoutSec), nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	// 204 = stopped, 304 = already stopped.
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotModified {
		return apiError(resp)
	}
	return nil
}

func (c *SocketClient) RemoveContainer(ctx context.Context, name string) error {
	resp, err := c.doRequest(ctx, "DELETE", "/containers/"+url.PathEscape(name), nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNoContent {
		return apiError(resp)
	}
	return nil
}

func (c *SocketClient) CreateContainer(ctx context.Context, spec ContainerSpec) (string, error) {
	body := createRequest{
		Image:      spec.Image,
		Env:        spec.Env,
		Cmd:        spec.Cmd,
		Entrypoint: spec.Entrypoint,
	}
	body.HostConfig.Binds = spec.Binds
	body.HostConfig.NetworkMode = spec.NetworkMode
	// Build a set of destinations already covered by Binds to avoid duplicates.
	// Docker inspect returns all mounts including those specified via Binds.
	bindDests := make(map[string]bool, len(spec.Binds))
	for _, b := range spec.Binds {
		parts := strings.SplitN(b, ":", 3)
		if len(parts) >= 2 {
			bindDests[parts[1]] = true
		}
	}
	for _, m := range spec.Mounts {
		// Skip mounts that are already specified via Binds to avoid duplicates.
		if bindDests[m.Destination] {
			continue
		}
		mountType := m.Type
		if mountType == "" {
			mountType = "volume"
		}
		// For volume mounts, use the volume Name as Source instead of the
		// host filesystem path. Docker inspect returns the host mountpoint
		// in Source (e.g. /var/lib/docker/volumes/myvolume/_data) but the
		// create API expects the volume name in Source.
		source := m.Source
		if mountType == "volume" && m.Name != "" {
			source = m.Name
		}
		body.HostConfig.Mounts = append(body.HostConfig.Mounts, createMount{
			Type:     mountType,
			Source:   source,
			Target:   m.Destination,
			ReadOnly: m.ReadOnly,
		})
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("marshal create request: %w", err)
	}

	resp, err := c.doRequest(ctx, "POST",
		"/containers/create?name="+url.QueryEscape(spec.Name),
		bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		return "", apiError(resp)
	}

	var cr createResponseBody
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		return "", fmt.Errorf("decode create response: %w", err)
	}
	return cr.ID, nil
}

func (c *SocketClient) StartContainer(ctx context.Context, id string) error {
	resp, err := c.doRequest(ctx, "POST", "/containers/"+url.PathEscape(id)+"/start", nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	// 204 = started, 304 = already running.
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotModified {
		return apiError(resp)
	}
	return nil
}

func (c *SocketClient) ExecInContainer(ctx context.Context, name string, cmd []string) error {
	// Step 1: Create exec instance.
	createBody := execCreateRequest{
		Cmd:          cmd,
		AttachStdout: true,
		AttachStderr: true,
	}
	payload, err := json.Marshal(createBody)
	if err != nil {
		return fmt.Errorf("marshal exec create: %w", err)
	}

	resp, err := c.doRequest(ctx, "POST",
		"/containers/"+url.PathEscape(name)+"/exec",
		bytes.NewReader(payload))
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		return apiError(resp)
	}

	var cr execCreateResponse
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		return fmt.Errorf("decode exec create response: %w", err)
	}

	// Step 2: Start the exec instance.
	startBody, _ := json.Marshal(map[string]bool{"Detach": false})
	resp2, err := c.doRequest(ctx, "POST",
		"/exec/"+url.PathEscape(cr.ID)+"/start",
		bytes.NewReader(startBody))
	if err != nil {
		return err
	}
	defer func() { _ = resp2.Body.Close() }()

	if resp2.StatusCode != http.StatusOK {
		return apiError(resp2)
	}
	// Drain output so the exec completes.
	_, _ = io.Copy(io.Discard, resp2.Body)

	// Step 3: Check exit code.
	resp3, err := c.doRequest(ctx, "GET", "/exec/"+url.PathEscape(cr.ID)+"/json", nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp3.Body.Close() }()

	if resp3.StatusCode != http.StatusOK {
		return apiError(resp3)
	}

	var inspectResp execInspectResponse
	if err := json.NewDecoder(resp3.Body).Decode(&inspectResp); err != nil {
		return fmt.Errorf("decode exec inspect response: %w", err)
	}
	if inspectResp.ExitCode != 0 {
		return fmt.Errorf("exec exited with code %d", inspectResp.ExitCode)
	}
	return nil
}

func (c *SocketClient) doRequest(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.apiURL(path), body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.client.Do(req)
}

// apiError reads and formats a Docker API error response.
func apiError(resp *http.Response) error {
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	msg := strings.TrimSpace(string(data))
	// Try to extract the "message" field from a JSON error response.
	var errBody struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(data, &errBody) == nil && errBody.Message != "" {
		msg = errBody.Message
	}
	if msg == "" {
		msg = resp.Status
	}
	return fmt.Errorf("docker API %d: %s", resp.StatusCode, msg)
}

// Docker API JSON types for inspect response.

type inspectResponse struct {
	ID     string `json:"Id"`
	State  struct {
		Running bool `json:"Running"`
	} `json:"State"`
	Config struct {
		Image      string   `json:"Image"`
		Env        []string `json:"Env"`
		Cmd        []string `json:"Cmd"`
		Entrypoint []string `json:"Entrypoint"`
	} `json:"Config"`
	HostConfig struct {
		Binds       []string `json:"Binds"`
		NetworkMode string   `json:"NetworkMode"`
	} `json:"HostConfig"`
	Mounts []struct {
		Type        string `json:"Type"`
		Name        string `json:"Name"`
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
		RW          bool   `json:"RW"`
	} `json:"Mounts"`
	NetworkSettings struct {
		Networks map[string]json.RawMessage `json:"Networks"`
	} `json:"NetworkSettings"`
}

// Docker API JSON types for create request/response.

// createMount matches the Docker API's Mount object format used in HostConfig.Mounts.
type createMount struct {
	Type     string `json:"Type"`
	Source   string `json:"Source"`
	Target   string `json:"Target"`
	ReadOnly bool   `json:"ReadOnly"`
}

type createRequest struct {
	Image      string   `json:"Image"`
	Env        []string `json:"Env,omitempty"`
	Cmd        []string `json:"Cmd,omitempty"`
	Entrypoint []string `json:"Entrypoint,omitempty"`
	HostConfig struct {
		Binds       []string      `json:"Binds,omitempty"`
		Mounts      []createMount `json:"Mounts,omitempty"`
		NetworkMode string        `json:"NetworkMode,omitempty"`
	} `json:"HostConfig"`
}

type createResponseBody struct {
	ID string `json:"Id"`
}

// Docker API JSON types for exec create/inspect.

type execCreateRequest struct {
	Cmd          []string `json:"Cmd"`
	AttachStdout bool     `json:"AttachStdout"`
	AttachStderr bool     `json:"AttachStderr"`
}

type execCreateResponse struct {
	ID string `json:"Id"`
}

type execInspectResponse struct {
	ExitCode int `json:"ExitCode"`
}
