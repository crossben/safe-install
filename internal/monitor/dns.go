package monitor

import (
	"net"
	"strings"
)

// decodeC turns strace's C-escaped string back into bytes: \ooo octal,
// \xNN hex, \n \t \r \v \f \a \b, \" and \\.
func decodeC(s string) []byte {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' || i+1 == len(s) {
			out = append(out, c)
			continue
		}
		i++
		switch e := s[i]; {
		case e >= '0' && e <= '7':
			v, n := 0, 0
			for n < 3 && i < len(s) && s[i] >= '0' && s[i] <= '7' {
				v = v*8 + int(s[i]-'0')
				i++
				n++
			}
			i--
			out = append(out, byte(v))
		case e == 'x' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]):
			out = append(out, hexVal(s[i+1])<<4|hexVal(s[i+2]))
			i += 2
		default:
			if v, ok := cEscapes[e]; ok {
				out = append(out, v)
			} else {
				out = append(out, e) // \" \\ \' and unknown escapes stand for themselves
			}
		}
	}
	return out
}

var cEscapes = map[byte]byte{'n': '\n', 't': '\t', 'r': '\r', 'v': '\v', 'f': '\f', 'a': '\a', 'b': '\b'}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func hexVal(c byte) byte {
	switch {
	case c >= 'a':
		return c - 'a' + 10
	case c >= 'A':
		return c - 'A' + 10
	}
	return c - '0'
}

// parseDNS reads a DNS response and maps each A/AAAA address to the name
// that was asked for (not intermediate CNAMEs). Truncated or malformed
// messages yield what could be read; nothing here panics or loops.
func parseDNS(b []byte) map[string]string {
	if len(b) < 12 || b[2]&0x80 == 0 { // header, QR bit: a response
		return nil
	}
	qd := int(b[4])<<8 | int(b[5])
	an := int(b[6])<<8 | int(b[7])
	if qd != 1 || an == 0 {
		return nil
	}
	name, off, ok := readName(b, 12)
	if !ok || off+4 > len(b) {
		return nil
	}
	off += 4 // qtype, qclass
	out := map[string]string{}
	for i := 0; i < an; i++ {
		_, next, ok := readName(b, off)
		if !ok || next+10 > len(b) {
			break
		}
		typ := int(b[next])<<8 | int(b[next+1])
		rdlen := int(b[next+8])<<8 | int(b[next+9])
		data := next + 10
		if data+rdlen > len(b) {
			break
		}
		switch {
		case typ == 1 && rdlen == 4, typ == 28 && rdlen == 16:
			out[net.IP(b[data:data+rdlen]).String()] = name
		}
		off = data + rdlen
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// readName reads a (possibly compressed) domain name at off and returns it
// and the offset just after it in the original position.
func readName(b []byte, off int) (string, int, bool) {
	var labels []string
	end := -1
	for jumps := 0; jumps < 16; {
		if off >= len(b) {
			return "", 0, false
		}
		l := int(b[off])
		switch {
		case l == 0:
			if end < 0 {
				end = off + 1
			}
			return strings.Join(labels, "."), end, len(labels) > 0
		case l&0xc0 == 0xc0:
			if off+1 >= len(b) {
				return "", 0, false
			}
			if end < 0 {
				end = off + 2
			}
			off = (l&0x3f)<<8 | int(b[off+1])
			jumps++
		default:
			if off+1+l > len(b) || len(labels) > 127 {
				return "", 0, false
			}
			labels = append(labels, string(b[off+1:off+1+l]))
			off += 1 + l
		}
	}
	return "", 0, false
}
