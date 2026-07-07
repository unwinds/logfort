package notify

import (
	"context"
	"crypto/tls"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"strings"
	"time"
)

type emailNotifier struct {
	addr string // "host:port"
	host string // hostname part, for TLS SNI and AUTH
	user string
	pass string
	from string
	to   []string
}

// NewEmail returns a Notifier that delivers alerts over SMTP.
// addr is "host:port" (bare hostnames default to :587); port 465 means
// implicit TLS, any other port upgrades via STARTTLS when the server offers
// it. user may be empty for unauthenticated relays; to is a comma-separated
// recipient list.
func NewEmail(addr, user, pass, from, to string) Notifier {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// No port given — use the standard submission port.
		host = addr
		addr = net.JoinHostPort(addr, "587")
	}
	var rcpts []string
	for _, r := range strings.Split(to, ",") {
		if r = strings.TrimSpace(r); r != "" {
			rcpts = append(rcpts, r)
		}
	}
	return &emailNotifier{addr: addr, host: host, user: user, pass: pass, from: from, to: rcpts}
}

func (e *emailNotifier) Name() string { return "email" }

func (e *emailNotifier) Send(ctx context.Context, msg Message) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", e.addr)
	if err != nil {
		return fmt.Errorf("smtp dial: %w", err)
	}
	// net/smtp has no context support past the dial; a connection deadline
	// bounds every subsequent read/write of the session.
	deadline := time.Now().Add(15 * time.Second)
	if dl, ok := ctx.Deadline(); ok {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)

	if _, port, err := net.SplitHostPort(e.addr); err == nil && port == "465" {
		conn = tls.Client(conn, &tls.Config{ServerName: e.host})
	}
	c, err := smtp.NewClient(conn, e.host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("smtp handshake: %w", err)
	}
	defer c.Close()

	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(&tls.Config{ServerName: e.host}); err != nil {
			return fmt.Errorf("smtp starttls: %w", err)
		}
	}
	if e.user != "" {
		// PlainAuth itself refuses to send credentials over an unencrypted
		// connection to a non-localhost server.
		if err := c.Auth(smtp.PlainAuth("", e.user, e.pass, e.host)); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	if err := c.Mail(e.from); err != nil {
		return fmt.Errorf("smtp mail from: %w", err)
	}
	for _, rcpt := range e.to {
		if err := c.Rcpt(rcpt); err != nil {
			return fmt.Errorf("smtp rcpt %s: %w", rcpt, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	if _, err := w.Write([]byte(e.render(msg))); err != nil {
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp send: %w", err)
	}
	return c.Quit()
}

// render builds the RFC 5322 message. The DATA dot-writer converts the \n
// line endings to CRLF on the wire.
func (e *emailNotifier) render(msg Message) string {
	var b strings.Builder
	fmt.Fprintf(&b, "From: LogFort <%s>\n", e.from)
	fmt.Fprintf(&b, "To: %s\n", strings.Join(e.to, ", "))
	fmt.Fprintf(&b, "Subject: %s\n", mime.QEncoding.Encode("utf-8", sanitizeHeaderValue(msg.Title)))
	fmt.Fprintf(&b, "Date: %s\n", time.Unix(msg.TS, 0).UTC().Format(time.RFC1123Z))
	b.WriteString("MIME-Version: 1.0\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\n")
	b.WriteString("Content-Transfer-Encoding: 8bit\n")
	b.WriteString("\n")
	b.WriteString(msg.Body)
	b.WriteString("\n")
	if msg.IP != "" {
		fmt.Fprintf(&b, "\nIP: %s\n", msg.IP)
	}
	if msg.Country != "" {
		fmt.Fprintf(&b, "Country: %s\n", msg.Country)
	}
	return b.String()
}
