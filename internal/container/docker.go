package container

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"time"
)

// ContainerClient abstracts Docker Engine API operations for testability.
// A production implementation wraps github.com/docker/docker/client.Client.
type ContainerClient interface { //nolint:revive // stuttering accepted for clarity
	InspectContainer(ctx context.Context, name string) (ContainerState, error)
	StopContainer(ctx context.Context, name string, timeoutSec int) error
	RemoveContainer(ctx context.Context, name string) error
	CreateContainer(ctx context.Context, spec ContainerSpec) (string, error)
	StartContainer(ctx context.Context, id string) error
	ExecInContainer(ctx context.Context, name string, cmd []string) error
}

// ContainerState holds the result of inspecting a container.
type ContainerState struct { //nolint:revive // stuttering accepted for clarity
	ID          string
	Image       string
	Env         []string
	Running     bool
	Mounts      []Mount
	Binds       []string // HostConfig.Binds preserving "source:dest:mode" format
	Networks    []string
	NetworkMode string
	Cmd         []string
	Entrypoint  []string
}

// Mount represents a container volume mount.
type Mount struct {
	Type        string
	Name        string // Volume name (for type=volume). Empty for bind mounts.
	Source      string
	Destination string
	ReadOnly    bool
}

// ContainerSpec holds parameters for creating a container.
type ContainerSpec struct { //nolint:revive // stuttering accepted for clarity
	Name        string
	Image       string
	Env         []string
	Mounts      []Mount
	Binds       []string // HostConfig.Binds preserving "source:dest:mode" format
	Networks    []string
	NetworkMode string
	Cmd         []string
	Entrypoint  []string
}

// DockerManager manages Docker container lifecycle for credential rotation.
// It implements the ContainerManager interface.
type DockerManager struct {
	client        ContainerClient
	containerName string
}

// NewDockerManager creates a new Docker container manager.
func NewDockerManager(client ContainerClient, containerName string) *DockerManager {
	return &DockerManager{
		client:        client,
		containerName: containerName,
	}
}

// InjectEnvVars writes environment variables into the agent container's env
// file (~/.openclaw/.env) via docker exec and then signals the agent to reload.
// Each key in envMap is an env var name and the value is the phantom token.
// When fullReplace is true the file is truncated before writing so stale
// entries are removed. When false, entries are merged in-place.
func (m *DockerManager) InjectEnvVars(ctx context.Context, envMap map[string]string, fullReplace bool) error {
	if len(envMap) == 0 && !fullReplace {
		return nil
	}

	script, err := BuildEnvInjectionScript(envMap, false, fullReplace)
	if err != nil {
		return fmt.Errorf("build env injection script: %w", err)
	}

	if execErr := m.client.ExecInContainer(ctx, m.containerName,
		[]string{"sh", "-c", script}); execErr != nil {
		return fmt.Errorf("inject env vars: %w", execErr)
	}

	// Signal the agent to reload secrets from the updated env file.
	if reloadErr := m.ReloadSecrets(ctx); reloadErr != nil {
		log.Printf("env vars injected but secrets reload failed: %v", reloadErr)
	}

	return nil
}

// ReloadSecrets signals the openclaw gateway to re-read secrets via WebSocket RPC.
func (m *DockerManager) ReloadSecrets(ctx context.Context) error {
	return m.client.ExecInContainer(ctx, m.containerName,
		[]string{"node", "-e", reloadSecretsScript})
}

// reloadSecretsScript is a Node.js one-liner that sends a secrets.reload
// RPC to the openclaw gateway via WebSocket. It reads the gateway config
// from disk to discover the port and auth token. This bypasses the openclaw
// CLI which hangs in container/non-TTY environments.
const reloadSecretsScript = `const fs=require("fs"),http=require("http"),crypto=require("crypto");` +
	`let port=18789,token="";` +
	`try{const c=JSON.parse(fs.readFileSync(process.env.HOME+"/.openclaw/openclaw.json","utf8"));` +
	`port=c.gateway?.port||18789;token=c.gateway?.auth?.token||"";}catch(e){}` +
	`const key=crypto.randomBytes(16).toString("base64");` +
	`const req=http.request({hostname:"127.0.0.1",port,path:"/",headers:{` +
	`"Upgrade":"websocket","Connection":"Upgrade",` +
	`"Sec-WebSocket-Key":key,"Sec-WebSocket-Version":"13",` +
	`"Authorization":"Bearer "+token}});` +
	`req.on("upgrade",(res,socket)=>{` +
	`const id=crypto.randomUUID();` +
	`const msg=JSON.stringify({type:"req",id,method:"secrets.reload"});` +
	`const p=Buffer.from(msg),mask=crypto.randomBytes(4);` +
	`let h;if(p.length<126){h=Buffer.alloc(2);h[0]=0x81;h[1]=0x80|p.length;}` +
	`else{h=Buffer.alloc(4);h[0]=0x81;h[1]=0x80|126;h.writeUInt16BE(p.length,2);}` +
	`const m=Buffer.alloc(p.length);for(let i=0;i<p.length;i++)m[i]=p[i]^mask[i%4];` +
	`socket.write(Buffer.concat([h,mask,m]));` +
	`socket.on("data",()=>{console.log("secrets reloaded");process.exit(0);});` +
	`setTimeout(()=>process.exit(0),5000);});` +
	`req.on("error",e=>{console.error(e.message);process.exit(1);});` +
	`req.setTimeout(5000,()=>{req.destroy();process.exit(1);});` +
	`req.end();`

// RestartWithEnv recreates the container with updated environment variables.
// It inspects the current container config, stops and removes it, creates a
// new container with the same config plus updated env vars, and starts it.
func (m *DockerManager) RestartWithEnv(ctx context.Context, envUpdates map[string]string) error {
	info, err := m.client.InspectContainer(ctx, m.containerName)
	if err != nil {
		return fmt.Errorf("inspect container: %w", err)
	}

	env := mergeEnv(info.Env, envUpdates)

	if err := m.client.StopContainer(ctx, m.containerName, 10); err != nil {
		return fmt.Errorf("stop container: %w", err)
	}
	if err := m.client.RemoveContainer(ctx, m.containerName); err != nil {
		return fmt.Errorf("remove container: %w", err)
	}

	newID, err := m.client.CreateContainer(ctx, ContainerSpec{
		Name:        m.containerName,
		Image:       info.Image,
		Env:         env,
		Mounts:      info.Mounts,
		Binds:       info.Binds,
		Networks:    info.Networks,
		NetworkMode: info.NetworkMode,
		Cmd:         info.Cmd,
		Entrypoint:  info.Entrypoint,
	})
	if err != nil {
		return fmt.Errorf("create container: %w", err)
	}

	if err := m.client.StartContainer(ctx, newID); err != nil {
		return fmt.Errorf("start container: %w", err)
	}

	return nil
}

// Status returns container health information.
func (m *DockerManager) Status(ctx context.Context) (ContainerStatus, error) {
	info, err := m.client.InspectContainer(ctx, m.containerName)
	if err != nil {
		return ContainerStatus{}, err
	}
	return ContainerStatus{
		ID:      info.ID,
		Running: info.Running,
		Image:   info.Image,
	}, nil
}

// InjectMCPConfig writes an mcp-servers.json file to the shared MCP volume
// and signals the agent container to reload MCP configuration via docker exec.
// If exec fails, the agent picks up the config on next restart.
func (m *DockerManager) InjectMCPConfig(mcpDir, sluiceURL string) error {
	if err := WriteMCPConfig(mcpDir, sluiceURL); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if execErr := m.client.ExecInContainer(ctx, m.containerName,
		[]string{"openclaw", "mcp", "reload"}); execErr != nil {
		path := filepath.Join(mcpDir, "mcp-servers.json")
		log.Printf("MCP config written to %s but exec reload failed: %v", path, execErr)
	}
	return nil
}

// InjectCACert is a no-op for Docker. Docker handles CA trust via compose
// volumes and SSL_CERT_FILE env vars set at container creation time.
func (m *DockerManager) InjectCACert(_ context.Context, _, _ string) error {
	return nil
}

// Runtime returns RuntimeDocker.
func (m *DockerManager) Runtime() Runtime {
	return RuntimeDocker
}

// Stop stops the agent container.
func (m *DockerManager) Stop(ctx context.Context) error {
	return m.client.StopContainer(ctx, m.containerName, 10)
}

// mergeEnv merges updates into an existing environment variable list.
// Existing variables are updated in place. New variables are appended.
// Variables with an empty string value in updates are removed.
// Insertion order of existing variables is preserved.
func mergeEnv(existing []string, updates map[string]string) []string {
	envMap := make(map[string]string, len(existing))
	order := make([]string, 0, len(existing))
	for _, e := range existing {
		k, v, _ := strings.Cut(e, "=")
		if _, exists := envMap[k]; !exists {
			order = append(order, k)
		}
		envMap[k] = v
	}
	for k, v := range updates {
		if _, exists := envMap[k]; !exists {
			order = append(order, k)
		}
		envMap[k] = v
	}
	result := make([]string, 0, len(order))
	for _, k := range order {
		v := envMap[k]
		// Empty value in updates signals removal.
		if _, isUpdate := updates[k]; isUpdate && v == "" {
			continue
		}
		result = append(result, k+"="+v)
	}
	return result
}
