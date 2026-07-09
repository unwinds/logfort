package threat

import (
	"strings"
	"testing"
)

func TestLookup(t *testing.T) {
	const data = `
# comment line
203.0.113.5
198.51.100.0/24
2001:db8::/32
10.0.0.1 ; some feed annotation
not-an-ip
`
	l, err := parse("testlist", strings.NewReader(data))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := l.Count(); got != 4 {
		t.Fatalf("Count: got %d, want 4", got)
	}
	cases := []struct {
		ip   string
		want string
	}{
		{"203.0.113.5", "testlist"},        // exact
		{"198.51.100.42", "testlist"},      // inside /24
		{"198.51.101.1", ""},               // outside /24
		{"2001:db8::1", "testlist"},        // inside v6 prefix
		{"::ffff:203.0.113.5", "testlist"}, // v4-mapped v6 normalises to the exact entry
		{"10.0.0.1", "testlist"},           // annotation stripped
		{"8.8.8.8", ""},                    // not listed
		{"garbage", ""},                    // unparseable
	}
	for _, c := range cases {
		if got := l.Lookup(c.ip); got != c.want {
			t.Errorf("Lookup(%q): got %q, want %q", c.ip, got, c.want)
		}
	}
}

// TestLookupMultiplePrefixLengths exercises the per-length prefix bucketing:
// several distinct CIDR lengths (and both families) must all resolve correctly,
// including an address inside a broad prefix but outside a narrower one.
func TestLookupMultiplePrefixLengths(t *testing.T) {
	const data = `
10.0.0.0/8
10.1.0.0/16
10.1.2.0/24
192.168.1.100/32
2001:db8:abcd::/48
`
	l, err := parse("multi", strings.NewReader(data))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := l.Count(); got != 5 {
		t.Fatalf("Count: got %d, want 5", got)
	}
	cases := []struct {
		ip   string
		want string
	}{
		{"10.1.2.42", "multi"},          // inside /24 (and /16, /8)
		{"10.1.9.9", "multi"},           // inside /16 (and /8) but not /24
		{"10.9.9.9", "multi"},           // inside /8 only
		{"11.0.0.1", ""},                // outside every 10.x prefix
		{"192.168.1.100", "multi"},      // exact /32
		{"192.168.1.101", ""},           // just outside the /32
		{"2001:db8:abcd:1::5", "multi"}, // inside the v6 /48
		{"2001:db8:abce::1", ""},        // outside the v6 /48
	}
	for _, c := range cases {
		if got := l.Lookup(c.ip); got != c.want {
			t.Errorf("Lookup(%q): got %q, want %q", c.ip, got, c.want)
		}
	}
}

func TestNilAndEmptySafe(t *testing.T) {
	var l *List
	if l.Lookup("1.2.3.4") != "" {
		t.Error("nil list should return empty")
	}
	if l.Count() != 0 || l.Name() != "" {
		t.Error("nil list accessors should be zero")
	}
	empty, _ := parse("e", strings.NewReader("# only comments\n"))
	if empty.Lookup("1.2.3.4") != "" {
		t.Error("empty list should return empty")
	}
}
