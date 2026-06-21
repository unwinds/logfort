package geo

import (
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
