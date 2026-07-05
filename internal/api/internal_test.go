package api

import (
	"net/http/httptest"
	"testing"
	"time"
)

// Sustained requests faster than one per 1/rate second must not starve the
// bucket: with integer token math each sub-token refill rounded to zero while
// `last` still advanced, so the limiter never recovered.
func TestRateLimiter_RefillsUnderSustainedLoad(t *testing.T) {
	rl := newRateLimiter(10, 5)

	// Drain the burst.
	for i := 0; i < 5; i++ {
		if !rl.Allow() {
			t.Fatalf("burst request %d denied", i)
		}
	}
	if rl.Allow() {
		t.Fatal("bucket should be empty after burst")
	}

	// Hammer with tiny intervals (~5ms each, 0.05 token per tick at 10/s).
	allowed := 0
	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		if rl.Allow() {
			allowed++
		}
		time.Sleep(5 * time.Millisecond)
	}
	if allowed == 0 {
		t.Fatal("limiter never refilled under sustained sub-token-interval load")
	}
}

func TestClientIP(t *testing.T) {
	cases := []struct {
		name       string
		remoteAddr string
		xff        string
		want       string
	}{
		{"direct public", "203.0.113.7:1234", "", "203.0.113.7"},
		{"public peer ignores XFF", "203.0.113.7:1234", "198.51.100.1", "203.0.113.7"},
		{"local proxy uses last XFF hop", "127.0.0.1:5555", "198.51.100.1", "198.51.100.1"},
		{"local proxy multi-hop XFF", "127.0.0.1:5555", "10.1.1.1, 198.51.100.2", "198.51.100.2"},
		{"local proxy garbage XFF falls back", "127.0.0.1:5555", "not-an-ip", "127.0.0.1"},
		{"ipv4-mapped peer normalized", "[::ffff:192.168.1.10]:443", "198.51.100.3", "198.51.100.3"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tc.remoteAddr
			if tc.xff != "" {
				r.Header.Set("X-Forwarded-For", tc.xff)
			}
			if got := clientIP(r); got != tc.want {
				t.Errorf("clientIP() = %q, want %q", got, tc.want)
			}
		})
	}
}
