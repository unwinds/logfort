package responder_test

import (
	"context"
	"testing"

	"github.com/unwinds/sshwatch/internal/responder"
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
