package webhook

import (
	"net"
)

// resolveHost returns numeric addresses for a host. Literal IPs are used as
// -is; DNS names are resolved so redirect-free SSRF checks cover the actual
// destination.
func resolveHost(host string) []net.IP {
	host = stripBrackets(host)
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		// Unresolvable names are blocked: treat as an unspecified address.
		return []net.IP{{}}
	}
	return ips
}

func stripBrackets(host string) string {
	if len(host) >= 2 && host[0] == '[' && host[len(host)-1] == ']' {
		return host[1 : len(host)-1]
	}
	return host
}

func isBlockedAddr(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() {
		return true
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || isCarrierGradeNAT(ip)
}

// IsPrivate does not cover 100.64.0.0/10 on older Go releases; check it too.
func isCarrierGradeNAT(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	return ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127
}
