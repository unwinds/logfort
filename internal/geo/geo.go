package geo

import (
	"fmt"
	"net"

	"github.com/oschwald/maxminddb-golang"
)

// Info holds geolocation data for an IP address.
type Info struct {
	Country string
	City    string
	Lat     float64
	Lon     float64
	ASN     string
}

// Looker resolves an IP string to geolocation data.
type Looker interface {
	Lookup(ip string) Info
}

// NoopLooker returns empty Info for every IP.
// Used when no GeoIP database is configured.
type NoopLooker struct{}

func (NoopLooker) Lookup(string) Info { return Info{} }

// DB wraps a MaxMind-format mmdb file (GeoLite2-City or DB-IP Lite City).
type DB struct {
	reader *maxminddb.Reader
}

// Open opens the mmdb at path. Returns an error if the file is missing or corrupt.
func Open(path string) (*DB, error) {
	r, err := maxminddb.Open(path)
	if err != nil {
		return nil, err
	}
	return &DB{reader: r}, nil
}

// Close releases the mmdb file handle.
func (d *DB) Close() error { return d.reader.Close() }

// Lookup returns geolocation data for the given IP string.
// Returns empty Info on any error (unparseable IP, not found in DB, etc.).
func (d *DB) Lookup(ipStr string) Info {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return Info{}
	}

	var rec struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
		City struct {
			Names map[string]string `maxminddb:"names"`
		} `maxminddb:"city"`
		Location struct {
			Latitude  float64 `maxminddb:"latitude"`
			Longitude float64 `maxminddb:"longitude"`
		} `maxminddb:"location"`
	}

	if err := d.reader.Lookup(ip, &rec); err != nil {
		return Info{}
	}

	return Info{
		Country: rec.Country.ISOCode,
		City:    rec.City.Names["en"],
		Lat:     rec.Location.Latitude,
		Lon:     rec.Location.Longitude,
	}
}

// ASNDB wraps an ASN-format mmdb file (GeoLite2-ASN or DB-IP ASN Lite).
type ASNDB struct {
	reader *maxminddb.Reader
}

// OpenASN opens the ASN mmdb at path.
func OpenASN(path string) (*ASNDB, error) {
	r, err := maxminddb.Open(path)
	if err != nil {
		return nil, err
	}
	return &ASNDB{reader: r}, nil
}

// Close releases the mmdb file handle.
func (d *ASNDB) Close() error { return d.reader.Close() }

// LookupASN returns "AS<number> <organization>" for the IP, or "" when the IP
// is unparseable or not in the database.
func (d *ASNDB) LookupASN(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	var rec struct {
		Number uint   `maxminddb:"autonomous_system_number"`
		Org    string `maxminddb:"autonomous_system_organization"`
	}
	if err := d.reader.Lookup(ip, &rec); err != nil || rec.Number == 0 {
		return ""
	}
	asn := fmt.Sprintf("AS%d", rec.Number)
	if rec.Org != "" {
		asn += " " + rec.Org
	}
	return asn
}

// WithASN combines a city Looker with an optional ASN database. Lookup fills
// Info from the city source first, then overlays the ASN string. Either part
// may be missing — the other still works.
type WithASN struct {
	City Looker
	ASN  *ASNDB
}

// Lookup implements Looker.
func (w WithASN) Lookup(ip string) Info {
	var info Info
	if w.City != nil {
		info = w.City.Lookup(ip)
	}
	if w.ASN != nil {
		info.ASN = w.ASN.LookupASN(ip)
	}
	return info
}
