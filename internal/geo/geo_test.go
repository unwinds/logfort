package geo_test

import (
	"testing"

	"github.com/unwinds/logfort/internal/geo"
)

func TestNoopLooker(t *testing.T) {
	var l geo.Looker = geo.NoopLooker{}

	for _, ip := range []string{"203.0.113.5", "::1", "invalid", ""} {
		info := l.Lookup(ip)
		if info.Country != "" || info.City != "" || info.Lat != 0 || info.Lon != 0 {
			t.Errorf("NoopLooker returned non-empty info for %q: %+v", ip, info)
		}
	}
}

func TestOpenMissingDB(t *testing.T) {
	_, err := geo.Open("/nonexistent/geo.mmdb")
	if err == nil {
		t.Fatal("expected error opening missing mmdb, got nil")
	}
}
