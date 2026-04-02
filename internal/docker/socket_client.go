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
	defer resp.Body.Close()

	// 204 = started, 304 = already running.
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotModified {
		return apiError(resp)
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
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
		RW          bool   `json:"RW"`
	} `json:"Mounts"`
	NetworkSettings struct {
		Networks map[string]json.RawMessage `json:"Networks"`
	} `json:"NetworkSettings"`
}

// Docker API JSON types for create request/response.

type createRequest struct {
	Image      string   `json:"Image"`
	Env        []string `json:"Env,omitempty"`
	Cmd        []string `json:"Cmd,omitempty"`
	Entrypoint []string `json:"Entrypoint,omitempty"`
	HostConfig struct {
		Binds       []string `json:"Binds,omitempty"`
		NetworkMode string   `json:"NetworkMode,omitempty"`
	} `json:"HostConfig"`
}

type createResponseBody struct {
	ID string `json:"Id"`
}
