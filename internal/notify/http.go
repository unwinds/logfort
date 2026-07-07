package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// maxErrBody caps how much of an error response body is kept for error messages.
const maxErrBody = 512

// postJSON POSTs payload to url and returns the final status code plus up to
// maxErrBody bytes of the response body. One retry is attempted on HTTP 429
// and 5xx — Telegram and Discord both rate-limit with 429 and honor
// Retry-After — with the wait capped so a single Send stays well inside the
// dispatcher's per-event budget.
func postJSON(ctx context.Context, client *http.Client, url string, payload any) (int, []byte, error) {
	return postJSONHdr(ctx, client, url, payload, nil)
}

// postJSONHdr is postJSON with extra request headers (e.g. Gotify's
// X-Gotify-Key). Content-Type is always application/json.
func postJSONHdr(ctx context.Context, client *http.Client, url string, payload any, hdr map[string]string) (int, []byte, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return 0, nil, err
	}
	if hdr == nil {
		hdr = map[string]string{}
	}
	hdr["Content-Type"] = "application/json"

	status, body, err := doPost(ctx, client, url, data, hdr)
	if err == nil && (status == http.StatusTooManyRequests || status >= 500) {
		wait := retryAfter(body, 2*time.Second)
		select {
		case <-time.After(wait):
			status, body, err = doPost(ctx, client, url, data, hdr)
		case <-ctx.Done():
			return status, body, nil // report the original response, not ctx error
		}
	}
	return status, body, err
}

func doPost(ctx context.Context, client *http.Client, url string, data []byte, hdr map[string]string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return 0, nil, err
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrBody))
	// Drain the remainder so the keep-alive connection can be reused.
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, body, nil
}

// retryAfter extracts a retry delay from a rate-limit response body.
// Telegram: {"parameters":{"retry_after":N}} (seconds); Discord:
// {"retry_after":N} (seconds, possibly fractional). Falls back to def,
// capped at 5s so one retry never blocks a Send for long.
func retryAfter(body []byte, def time.Duration) time.Duration {
	var tg struct {
		Parameters struct {
			RetryAfter float64 `json:"retry_after"`
		} `json:"parameters"`
		RetryAfter float64 `json:"retry_after"`
	}
	secs := 0.0
	if json.Unmarshal(body, &tg) == nil {
		secs = tg.Parameters.RetryAfter
		if secs == 0 {
			secs = tg.RetryAfter
		}
	}
	d := def
	if secs > 0 {
		d = time.Duration(secs * float64(time.Second))
	}
	if d > 5*time.Second {
		d = 5 * time.Second
	}
	return d
}

// httpError formats a delivery error including a body snippet — the body is
// where Telegram/Discord explain what actually went wrong ("chat not found",
// "Unknown Webhook", …).
func httpError(service string, status int, body []byte) error {
	snippet := string(bytes.TrimSpace(body))
	if snippet == "" {
		return fmt.Errorf("%s returned HTTP %d", service, status)
	}
	return fmt.Errorf("%s returned HTTP %d: %s", service, status, snippet)
}
