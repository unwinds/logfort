package notify

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSlack_Success(t *testing.T) {
	var gotText string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p struct {
			Text string `json:"text"`
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &p)
		gotText = p.Text
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	n := &slackNotifier{url: srv.URL, client: srv.Client()}
	if err := n.Send(context.Background(), testMsg()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !strings.Contains(gotText, "*t*") || !strings.Contains(gotText, "b") {
		t.Errorf("payload must contain bold title and body, got: %q", gotText)
	}
}

func TestSlack_ErrorIncludesBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("no_service"))
	}))
	defer srv.Close()

	n := &slackNotifier{url: srv.URL, client: srv.Client()}
	err := n.Send(context.Background(), testMsg())
	if err == nil || !strings.Contains(err.Error(), "no_service") {
		t.Errorf("error must include Slack response body, got: %v", err)
	}
}

func TestNtfy_SetsHeadersAndBody(t *testing.T) {
	var gotTitle, gotAuth, gotBody, gotPriority string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTitle = r.Header.Get("Title")
		gotAuth = r.Header.Get("Authorization")
		gotPriority = r.Header.Get("Priority")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		_, _ = w.Write([]byte(`{"id":"x"}`))
	}))
	defer srv.Close()

	n := &ntfyNotifier{url: srv.URL, token: "tok123", client: srv.Client()}
	if err := n.Send(context.Background(), testMsg()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if gotTitle != "t" || gotBody != "b" {
		t.Errorf("title/body mismatch: %q / %q", gotTitle, gotBody)
	}
	if gotAuth != "Bearer tok123" {
		t.Errorf("Authorization: %q", gotAuth)
	}
	if gotPriority != "high" {
		t.Errorf("ban events must be high priority, got %q", gotPriority)
	}
}

func TestNtfy_ErrorIncludesBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"forbidden"}`))
	}))
	defer srv.Close()

	n := &ntfyNotifier{url: srv.URL, client: srv.Client()}
	err := n.Send(context.Background(), testMsg())
	if err == nil || !strings.Contains(err.Error(), "forbidden") {
		t.Errorf("error must include ntfy response body, got: %v", err)
	}
}

func TestGotify_SendsTokenHeader(t *testing.T) {
	var gotKey, gotPath string
	var gotPayload map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("X-Gotify-Key")
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotPayload)
		_, _ = w.Write([]byte(`{"id":1}`))
	}))
	defer srv.Close()

	n := &gotifyNotifier{base: srv.URL, token: "app-token", client: srv.Client()}
	if err := n.Send(context.Background(), testMsg()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if gotKey != "app-token" {
		t.Errorf("X-Gotify-Key: %q", gotKey)
	}
	if gotPath != "/message" {
		t.Errorf("path: %q", gotPath)
	}
	if gotPayload["title"] != "t" || gotPayload["message"] != "b" {
		t.Errorf("payload: %v", gotPayload)
	}
}

func TestGotify_TrimsTrailingSlash(t *testing.T) {
	n := NewGotify("https://example.com/", "tok").(*gotifyNotifier)
	if n.base != "https://example.com" {
		t.Errorf("base: %q", n.base)
	}
}

// fakeSMTPServer speaks just enough SMTP (no TLS, no AUTH) to accept one
// message and return its DATA payload.
func fakeSMTPServer(t *testing.T) (addr string, data <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	ch := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		br := bufio.NewReader(conn)
		fmt.Fprintf(conn, "220 fake ESMTP\r\n")
		var body strings.Builder
		inData := false
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if inData {
				if strings.TrimRight(line, "\r\n") == "." {
					inData = false
					fmt.Fprintf(conn, "250 OK: queued\r\n")
					ch <- body.String()
					continue
				}
				body.WriteString(line)
				continue
			}
			cmd := strings.ToUpper(strings.TrimSpace(line))
			switch {
			case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
				fmt.Fprintf(conn, "250-fake\r\n250 8BITMIME\r\n")
			case strings.HasPrefix(cmd, "MAIL"), strings.HasPrefix(cmd, "RCPT"):
				fmt.Fprintf(conn, "250 OK\r\n")
			case strings.HasPrefix(cmd, "DATA"):
				fmt.Fprintf(conn, "354 End data with <CR><LF>.<CR><LF>\r\n")
				inData = true
			case strings.HasPrefix(cmd, "QUIT"):
				fmt.Fprintf(conn, "221 bye\r\n")
				return
			default:
				fmt.Fprintf(conn, "250 OK\r\n")
			}
		}
	}()
	return ln.Addr().String(), ch
}

func TestEmail_SendsMessage(t *testing.T) {
	addr, dataCh := fakeSMTPServer(t)

	n := NewEmail(addr, "", "", "logfort@example.com", "admin@example.com, ops@example.com")
	if err := n.Send(context.Background(), testMsg()); err != nil {
		t.Fatalf("Send: %v", err)
	}

	select {
	case data := <-dataCh:
		for _, want := range []string{"Subject: t", "From: LogFort <logfort@example.com>", "To: admin@example.com, ops@example.com", "b", "IP: 1.2.3.4"} {
			if !strings.Contains(data, want) {
				t.Errorf("message missing %q:\n%s", want, data)
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for message")
	}
}

func TestEmail_DialErrorSurfaces(t *testing.T) {
	// Port 1 on loopback is essentially guaranteed closed.
	n := NewEmail("127.0.0.1:1", "", "", "a@b", "c@d")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := n.Send(ctx, testMsg()); err == nil {
		t.Fatal("want dial error")
	}
}

func TestEmail_DefaultPort(t *testing.T) {
	n := NewEmail("smtp.example.com", "", "", "a@b", "c@d").(*emailNotifier)
	if n.addr != "smtp.example.com:587" {
		t.Errorf("addr: %q", n.addr)
	}
	if n.host != "smtp.example.com" {
		t.Errorf("host: %q", n.host)
	}
}
