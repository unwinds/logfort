package notify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testMsg() Message {
	return Message{Title: "t", Body: "b", IP: "1.2.3.4", EventType: "ban", TS: time.Now().Unix()}
}

func TestTelegram_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/botTOKEN/sendMessage" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"ok":true,"result":{}}`))
	}))
	defer srv.Close()

	n := &telegramNotifier{token: "TOKEN", chatID: "42", apiBase: srv.URL, client: srv.Client()}
	if err := n.Send(context.Background(), testMsg()); err != nil {
		t.Fatalf("Send: %v", err)
	}
}

func TestTelegram_ErrorIncludesDescription(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"ok":false,"error_code":400,"description":"Bad Request: chat not found"}`))
	}))
	defer srv.Close()

	n := &telegramNotifier{token: "TOKEN", chatID: "42", apiBase: srv.URL, client: srv.Client()}
	err := n.Send(context.Background(), testMsg())
	if err == nil {
		t.Fatal("want error for HTTP 400")
	}
	if !strings.Contains(err.Error(), "chat not found") {
		t.Errorf("error must surface Telegram description, got: %v", err)
	}
}

func TestTelegram_OKFalseWith200(t *testing.T) {
	// Defensive: treat ok:false as failure even if the status is 200.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":false,"description":"something odd"}`))
	}))
	defer srv.Close()

	n := &telegramNotifier{token: "TOKEN", chatID: "42", apiBase: srv.URL, client: srv.Client()}
	if err := n.Send(context.Background(), testMsg()); err == nil {
		t.Fatal("want error when ok:false")
	}
}

func TestDiscord_Success204(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	n := &discordNotifier{url: srv.URL, client: srv.Client()}
	if err := n.Send(context.Background(), testMsg()); err != nil {
		t.Fatalf("Send: %v", err)
	}
}

func TestWebhook_ErrorIncludesBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`invalid signature`))
	}))
	defer srv.Close()

	n := &webhookNotifier{url: srv.URL, client: srv.Client()}
	err := n.Send(context.Background(), testMsg())
	if err == nil || !strings.Contains(err.Error(), "invalid signature") {
		t.Errorf("error must include response body, got: %v", err)
	}
}

func TestPostJSON_RetriesOn429(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"retry_after":0.01}`))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	status, _, err := postJSON(context.Background(), srv.Client(), srv.URL, map[string]string{"a": "b"})
	if err != nil {
		t.Fatalf("postJSON: %v", err)
	}
	if status != http.StatusNoContent {
		t.Errorf("want 204 after retry, got %d", status)
	}
	if calls.Load() != 2 {
		t.Errorf("want exactly 2 requests, got %d", calls.Load())
	}
}

func TestPostJSON_NoRetryOn400(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	status, _, err := postJSON(context.Background(), srv.Client(), srv.URL, nil)
	if err != nil {
		t.Fatalf("postJSON: %v", err)
	}
	if status != http.StatusBadRequest {
		t.Errorf("status: %d", status)
	}
	if calls.Load() != 1 {
		t.Errorf("client errors must not be retried, got %d requests", calls.Load())
	}
}
