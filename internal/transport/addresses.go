package transport

import "net/netip"

// Pinned IANA special-purpose registries, both last updated 2025-10-09:
// https://www.iana.org/assignments/iana-ipv4-special-registry
// https://www.iana.org/assignments/iana-ipv6-special-registry
// Broad parent ranges deliberately include every more-specific assignment,
// even globally reachable special-purpose exceptions. Multicast is also denied.
var special = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.31.196.0/24"), netip.MustParsePrefix("192.52.193.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("192.175.48.0/24"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001::/23"), netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"), netip.MustParsePrefix("2620:4f:8000::/48"),
	netip.MustParsePrefix("3fff::/20"),
}

func allowedAddress(a netip.Addr, extra []netip.Prefix) bool {
	a = a.Unmap()
	if !a.IsValid() || a.Zone() != "" || !a.IsGlobalUnicast() {
		return false
	}
	// Only presently allocated global unicast space; this also excludes NAT64,
	// unspecified, ULA, link-local, and reserved/transition space outside it.
	if a.Is6() && !netip.MustParsePrefix("2000::/3").Contains(a) {
		return false
	}
	for _, p := range special {
		if p.Contains(a) {
			return false
		}
	}
	for _, p := range extra {
		if p.Contains(a) {
			return false
		}
	}
	return true
}
