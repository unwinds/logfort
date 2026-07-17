//go:build linux

package responder

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/google/nftables"
)

// NftablesResponder bans IPs by adding them to nftables sets.
// Requires CAP_NET_ADMIN and host network namespace (use cap_add: NET_ADMIN in Docker).
//
// Two sets are managed:
//
//	<set>  (type ipv4_addr) — IPv4 block list
//	<set>6 (type ipv6_addr) — IPv6 block list
//
// Reference them in your nftables rules:
//
//	nft add rule inet filter input ip  saddr @logfort_block  drop
//	nft add rule inet filter input ip6 saddr @logfort_block6 drop
type NftablesResponder struct {
	family nftables.TableFamily
	table  string
	setV4  string
	setV6  string
}

func newNftablesResponder(tableSpec, setName string) (Responder, error) {
	family, tableName, err := parseTableSpec(tableSpec)
	if err != nil {
		return nil, err
	}
	r := &NftablesResponder{
		family: family,
		table:  tableName,
		setV4:  setName,
		setV6:  setName + "6",
	}
	if err := r.ensureSets(); err != nil {
		return nil, fmt.Errorf("init nftables sets (CAP_NET_ADMIN required): %w", err)
	}
	return r, nil
}

func (r *NftablesResponder) Name() string { return "nftables" }

func (r *NftablesResponder) Ban(_ context.Context, ip string) error {
	c, err := nftables.New()
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("invalid IP: %s", ip)
	}
	tbl := &nftables.Table{Family: r.family, Name: r.table}
	if v4 := parsed.To4(); v4 != nil {
		return r.addElement(c, tbl, r.setV4, v4)
	}
	return r.addElement(c, tbl, r.setV6, parsed.To16())
}

func (r *NftablesResponder) Unban(_ context.Context, ip string) error {
	c, err := nftables.New()
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("invalid IP: %s", ip)
	}
	tbl := &nftables.Table{Family: r.family, Name: r.table}
	if v4 := parsed.To4(); v4 != nil {
		return r.delElement(c, tbl, r.setV4, v4)
	}
	return r.delElement(c, tbl, r.setV6, parsed.To16())
}

func (r *NftablesResponder) List(_ context.Context) ([]string, error) {
	c, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	tbl := &nftables.Table{Family: r.family, Name: r.table}

	var result []string
	for _, setName := range []string{r.setV4, r.setV6} {
		s, err := c.GetSetByName(tbl, setName)
		if err != nil {
			continue
		}
		elems, err := c.GetSetElements(s)
		if err != nil {
			continue
		}
		for _, el := range elems {
			if ip := net.IP(el.Key); ip != nil {
				result = append(result, ip.String())
			}
		}
	}
	return result, nil
}

func (r *NftablesResponder) ensureSets() error {
	c, err := nftables.New()
	if err != nil {
		return err
	}
	tbl := c.AddTable(&nftables.Table{Family: r.family, Name: r.table})

	if _, err := c.GetSetByName(tbl, r.setV4); err != nil {
		if err := c.AddSet(&nftables.Set{Table: tbl, Name: r.setV4, KeyType: nftables.TypeIPAddr}, nil); err != nil {
			return fmt.Errorf("add set %q: %w", r.setV4, err)
		}
	}
	if _, err := c.GetSetByName(tbl, r.setV6); err != nil {
		if err := c.AddSet(&nftables.Set{Table: tbl, Name: r.setV6, KeyType: nftables.TypeIP6Addr}, nil); err != nil {
			return fmt.Errorf("add set %q: %w", r.setV6, err)
		}
	}
	return c.Flush()
}

func (r *NftablesResponder) addElement(c *nftables.Conn, tbl *nftables.Table, setName string, key []byte) error {
	s, err := c.GetSetByName(tbl, setName)
	if err != nil {
		return fmt.Errorf("get set %q: %w", setName, err)
	}
	if err := c.SetAddElements(s, []nftables.SetElement{{Key: key}}); err != nil {
		return err
	}
	return c.Flush()
}

func (r *NftablesResponder) delElement(c *nftables.Conn, tbl *nftables.Table, setName string, key []byte) error {
	s, err := c.GetSetByName(tbl, setName)
	if err != nil {
		return fmt.Errorf("get set %q: %w", setName, err)
	}
	if err := c.SetDeleteElements(s, []nftables.SetElement{{Key: key}}); err != nil {
		return err
	}
	return c.Flush()
}

func parseTableSpec(spec string) (nftables.TableFamily, string, error) {
	parts := strings.SplitN(strings.TrimSpace(spec), " ", 2)
	if len(parts) != 2 {
		return 0, "", fmt.Errorf("NFT_TABLE must be \"<family> <name>\", got %q", spec)
	}
	fam, err := tableFamily(parts[0])
	if err != nil {
		return 0, "", err
	}
	return fam, parts[1], nil
}

func tableFamily(s string) (nftables.TableFamily, error) {
	switch strings.ToLower(s) {
	case "inet":
		return nftables.TableFamilyINet, nil
	case "ip", "ipv4":
		return nftables.TableFamilyIPv4, nil
	case "ip6", "ipv6":
		return nftables.TableFamilyIPv6, nil
	case "arp":
		return nftables.TableFamilyARP, nil
	case "bridge":
		return nftables.TableFamilyBridge, nil
	case "netdev":
		return nftables.TableFamilyNetdev, nil
	default:
		return 0, fmt.Errorf("unknown nftables family %q", s)
	}
}
