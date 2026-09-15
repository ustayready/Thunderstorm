package redact

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// netMapper produces topology-preserving fakes for IPv4 addresses and CIDRs: if two real
// addresses share an n-bit prefix, their fakes share an n-bit prefix (so same-subnet
// co-membership and CIDR containment survive). Class is preserved (private->private,
// public->reserved 240/4) so exposure semantics ("internet-facing") stay true. The
// well-known "any" ranges are kept verbatim.
type netMapper struct{ salt []byte }

func newNetMapper(salt []byte) *netMapper { return &netMapper{salt: salt} }

// ipClass returns (classPrefixLen, fakeBase) for the address's class. fakeBase has only
// its top classPrefixLen bits set; the lower bits are filled by the prefix-preserving map.
func ipClass(v uint32) (int, uint32) {
	switch {
	case v>>24 == 10: // 10.0.0.0/8 private
		return 8, 10 << 24
	case v>>20 == (172<<4)|1: // 172.16.0.0/12 private
		return 12, (172 << 24) | (16 << 16)
	case v>>16 == (192<<8)|168: // 192.168.0.0/16 private
		return 16, (192 << 24) | (168 << 16)
	case v>>24 == 127: // loopback
		return 8, 127 << 24
	case v>>16 == (169<<8)|254: // link-local
		return 16, (169 << 24) | (254 << 16)
	case v>>22 == (100<<2)|1: // 100.64.0.0/10 CGNAT
		return 10, (100 << 24) | (64 << 16)
	default: // public -> reserved 240.0.0.0/4 (non-routable, huge, guaranteed non-real)
		return 4, 240 << 24
	}
}

// prefixPreserve maps the low (32-classLen) bits of v through a keyed, prefix-preserving
// permutation and ORs them onto fakeBase. Bit i of the output depends only on the real
// bits above it, which is exactly the property that preserves shared prefixes.
func (m *netMapper) prefixPreserve(v uint32) uint32 {
	classLen, base := ipClass(v)
	lowBits := 32 - classLen
	var out uint32
	var pfx uint32 // real bits seen so far (below the class prefix)
	for i := 0; i < lowBits; i++ {
		pos := uint(lowBits - 1 - i)
		realBit := (v >> pos) & 1
		mac := hmac.New(sha256.New, m.salt)
		var buf [12]byte
		binary.BigEndian.PutUint32(buf[0:], uint32(classLen))
		binary.BigEndian.PutUint32(buf[4:], uint32(i))
		binary.BigEndian.PutUint32(buf[8:], pfx)
		mac.Write(buf[:])
		fBit := uint32(mac.Sum(nil)[0]) & 1
		out |= (realBit ^ fBit) << pos
		pfx = (pfx << 1) | realBit
	}
	return base | out
}

func (m *netMapper) mapIPv4(v uint32) uint32 { return m.prefixPreserve(v) }

// MapIP returns a topology-preserving fake for an IPv4/IPv6 literal, or "" if s isn't one.
func (m *netMapper) MapIP(s string) string {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		if isAnyV4(v4) {
			return s // 0.0.0.0 kept
		}
		out := m.mapIPv4(binary.BigEndian.Uint32(v4))
		return fmt.Sprintf("%d.%d.%d.%d", byte(out>>24), byte(out>>16), byte(out>>8), byte(out))
	}
	// IPv6: keep ::, ::1; map global unicast into ULA fd00::/8 preserving lower structure.
	if ip.Equal(net.IPv6zero) || ip.Equal(net.IPv6loopback) {
		return s
	}
	return m.mapIPv6(ip)
}

// MapCIDR returns a topology-preserving fake CIDR (prefix length preserved), or "" if
// s isn't a CIDR. "0.0.0.0/0" and "::/0" are kept verbatim (semantic "any").
func (m *netMapper) MapCIDR(s string) string {
	s = strings.TrimSpace(s)
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		return ""
	}
	ones, bits := ipnet.Mask.Size()
	if ones == 0 {
		return s // /0 "any" kept
	}
	if bits == 32 {
		v := binary.BigEndian.Uint32(ipnet.IP.To4())
		out := m.mapIPv4(v)
		// zero the host bits so it's a clean network address at the same prefix length
		out &= ^uint32(0) << (32 - ones)
		return fmt.Sprintf("%d.%d.%d.%d/%d", byte(out>>24), byte(out>>16), byte(out>>8), byte(out), ones)
	}
	fake := m.mapIPv6(ipnet.IP)
	if i := strings.IndexByte(fake, '%'); i >= 0 {
		fake = fake[:i]
	}
	return fake + "/" + strconv.Itoa(ones)
}

func (m *netMapper) mapIPv6(ip net.IP) string {
	b := ip.To16()
	out := make([]byte, 16)
	out[0] = 0xfd // ULA fd00::/8, class-preserving-ish (private-use, non-global)
	// Prefix-preserving over the remaining 120 bits, byte-granular for simplicity.
	var pfx []byte
	for i := 1; i < 16; i++ {
		mac := hmac.New(sha256.New, m.salt)
		mac.Write([]byte("v6"))
		mac.Write([]byte{byte(i)})
		mac.Write(pfx)
		out[i] = b[i] ^ mac.Sum(nil)[0]
		pfx = append(pfx, b[i])
	}
	return net.IP(out).String()
}

func isAnyV4(v4 net.IP) bool { return v4[0] == 0 && v4[1] == 0 && v4[2] == 0 && v4[3] == 0 }
