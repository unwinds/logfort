package f2b

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	endMarker   = "<F2B_END_COMMAND>"
	closeMarker = "<F2B_CLOSE_COMMAND>"
	// DefaultSocketPath is where fail2ban creates its command socket.
	DefaultSocketPath = "/var/run/fail2ban/fail2ban.sock"

	defaultTimeout = 5 * time.Second
	maxResponse    = 4 << 20 // 4 MB — status of a large jail stays well below this
)

// Client executes fail2ban commands. It talks to the command socket directly
// (works inside a container with the socket mounted, no Python needed) and
// falls back to the fail2ban-client binary when the socket does not exist
// (bare-metal installs where logfort runs as a plain process).
type Client struct {
	SocketPath string
	Timeout    time.Duration
}

// NewClient returns a Client for the given socket path ("" = default).
func NewClient(socketPath string) *Client {
	if socketPath == "" {
		socketPath = DefaultSocketPath
	}
	return &Client{SocketPath: socketPath, Timeout: defaultTimeout}
}

// Available reports whether some way of reaching fail2ban exists: the command
// socket is present, or the fail2ban-client binary is in PATH.
func (c *Client) Available() bool {
	if _, err := os.Stat(c.SocketPath); err == nil {
		return true
	}
	_, err := exec.LookPath("fail2ban-client")
	return err == nil
}

// Exec runs a fail2ban command (e.g. "set", "sshd", "maxretry", "5") and
// returns the decoded response payload.
func (c *Client) Exec(ctx context.Context, args ...string) (any, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("f2b: empty command")
	}
	if _, err := os.Stat(c.SocketPath); err == nil {
		return c.execSocket(ctx, args)
	}
	return c.execCLI(ctx, args)
}

func (c *Client) execSocket(ctx context.Context, args []string) (any, error) {
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "unix", c.SocketPath)
	if err != nil {
		return nil, fmt.Errorf("f2b: dial %s: %w", c.SocketPath, err)
	}
	defer conn.Close()

	deadline := time.Now().Add(c.timeout())
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)

	msg := append(pickleCommand(args), []byte(endMarker)...)
	if _, err := conn.Write(msg); err != nil {
		return nil, fmt.Errorf("f2b: write: %w", err)
	}

	var buf bytes.Buffer
	tmp := make([]byte, 4096)
	for {
		n, rerr := conn.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
			if buf.Len() > maxResponse {
				return nil, fmt.Errorf("f2b: response exceeds %d bytes", maxResponse)
			}
			if bytes.HasSuffix(buf.Bytes(), []byte(endMarker)) {
				break
			}
		}
		if rerr != nil {
			return nil, fmt.Errorf("f2b: read: %w", rerr)
		}
	}
	// Politely tell the server we are done, mirroring fail2ban-client.
	_, _ = conn.Write(append([]byte(closeMarker), []byte(endMarker)...))

	payload := bytes.TrimSuffix(buf.Bytes(), []byte(endMarker))
	v, err := unpickle(payload)
	if err != nil {
		return nil, fmt.Errorf("f2b: decode response: %w", err)
	}
	return interpretResponse(v)
}

// interpretResponse unwraps fail2ban's (code, payload) response tuple.
func interpretResponse(v any) (any, error) {
	tup, ok := v.([]any)
	if !ok || len(tup) != 2 {
		return nil, fmt.Errorf("f2b: unexpected response shape: %s", Stringify(v))
	}
	code, ok := tup[0].(int64)
	if !ok {
		return nil, fmt.Errorf("f2b: unexpected response code: %s", Stringify(tup[0]))
	}
	if code != 0 {
		return nil, fmt.Errorf("f2b: server error: %s", Stringify(tup[1]))
	}
	return tup[1], nil
}

func (c *Client) execCLI(ctx context.Context, args []string) (any, error) {
	bin, err := exec.LookPath("fail2ban-client")
	if err != nil {
		return nil, fmt.Errorf("f2b: neither socket %s nor fail2ban-client available", c.SocketPath)
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = strings.TrimSpace(stdout.String())
		}
		if msg != "" {
			return nil, fmt.Errorf("f2b: fail2ban-client %s: %s", strings.Join(args, " "), msg)
		}
		return nil, fmt.Errorf("f2b: fail2ban-client %s: %w", strings.Join(args, " "), err)
	}
	return strings.TrimSpace(stdout.String()), nil
}

func (c *Client) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return defaultTimeout
}

// AsInt coerces an Exec result (socket int64 or CLI string output) to int64.
func AsInt(v any) (int64, bool) {
	switch t := v.(type) {
	case int64:
		return t, true
	case float64:
		return int64(t), true
	case string:
		var n int64
		if _, err := fmt.Sscanf(strings.TrimSpace(t), "%d", &n); err == nil {
			return n, true
		}
	}
	return 0, false
}
