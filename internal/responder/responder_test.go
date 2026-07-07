package responder_test

import (
	"context"
	"testing"

	"github.com/unwinds/logfort/internal/config"
	"github.com/unwinds/logfort/internal/responder"
)

func TestAllowlist(t *testing.T) {
	al, err := responder.ParseAllowlist([]string{
		"127.0.0.0/8",
		"10.0.0.0/8",
		"::1",
		"192.168.1.1",
	})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	cases := []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", true},
		{"127.255.0.1", true},
		{"10.1.2.3", true},
		{"192.168.1.1", true},
		{"::1", true},
		{"203.0.113.5", false},
		{"8.8.8.8", false},
		{"192.168.1.2", false},
	}
	for _, tc := range cases {
		got := al.Contains(tc.ip)
		if got != tc.want {
			t.Errorf("Contains(%q) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

func TestAllowlistInvalidEntry(t *testing.T) {
	_, err := responder.ParseAllowlist([]string{"not-an-ip"})
	if err == nil {
		t.Error("expected error for invalid entry")
	}
}

func TestAllowlistSetExtra(t *testing.T) {
	al, err := responder.ParseAllowlist([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if al.Contains("203.0.113.5") {
		t.Fatal("203.0.113.5 must not be allowlisted yet")
	}

	if err := al.SetExtra([]string{"203.0.113.5", "198.51.100.0/24"}); err != nil {
		t.Fatalf("SetExtra: %v", err)
	}
	for _, ip := range []string{"203.0.113.5", "198.51.100.77", "10.1.2.3"} {
		if !al.Contains(ip) {
			t.Errorf("Contains(%q) = false after SetExtra", ip)
		}
	}

	// Invalid entries must be rejected and leave the previous extra set intact.
	if err := al.SetExtra([]string{"bogus"}); err == nil {
		t.Error("want error for invalid extra entry")
	}
	if !al.Contains("203.0.113.5") {
		t.Error("failed SetExtra must not clear previous extra entries")
	}

	// Replacing the extra set drops entries not in the new set.
	if err := al.SetExtra([]string{"192.0.2.1"}); err != nil {
		t.Fatalf("SetExtra: %v", err)
	}
	if al.Contains("203.0.113.5") {
		t.Error("old extra entry must be gone after replacement")
	}
	if !al.Contains("192.0.2.1") || !al.Contains("10.1.2.3") {
		t.Error("new extra entry and base entries must remain")
	}
}

func TestIsPrivate(t *testing.T) {
	private := []string{"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.0.1", "::1", "fe80::1"}
	for _, ip := range private {
		if !responder.IsPrivate(ip) {
			t.Errorf("IsPrivate(%q) = false, want true", ip)
		}
	}
	public := []string{"8.8.8.8", "203.0.113.5", "2001:db8::1"}
	for _, ip := range public {
		if responder.IsPrivate(ip) {
			t.Errorf("IsPrivate(%q) = true, want false", ip)
		}
	}
}

func TestIsValid(t *testing.T) {
	if !responder.IsValid("1.2.3.4") {
		t.Error("IsValid(1.2.3.4) = false")
	}
	if !responder.IsValid("::1") {
		t.Error("IsValid(::1) = false")
	}
	if responder.IsValid("not-an-ip") {
		t.Error("IsValid(not-an-ip) = true")
	}
	if responder.IsValid("") {
		t.Error("IsValid('') = true")
	}
}

func TestNewWithBadAllowlistAndDisabledResponder(t *testing.T) {
	// A bad IGNORE_IPS entry must not kill startup when responder is disabled.
	cfg := &config.Config{
		ResponderEnabled: false,
		IgnoreIPs:        []string{"not-valid"},
	}
	r, al, err := responder.New(cfg)
	if err != nil {
		t.Fatalf("New() must not fail when responder is disabled: %v", err)
	}
	if r == nil || al == nil {
		t.Error("want non-nil Responder and Allowlist")
	}
}

func TestNoopResponder(t *testing.T) {
	ctx := context.Background()
	r := responder.NoopResponder{}
	if err := r.Ban(ctx, "1.2.3.4"); err != nil {
		t.Errorf("Ban: %v", err)
	}
	if err := r.Unban(ctx, "1.2.3.4"); err != nil {
		t.Errorf("Unban: %v", err)
	}
	ips, err := r.List(ctx)
	if err != nil {
		t.Errorf("List: %v", err)
	}
	if len(ips) != 0 {
		t.Errorf("List: want empty, got %v", ips)
	}
	if r.Name() != "noop" {
		t.Errorf("Name: %q", r.Name())
	}
}
