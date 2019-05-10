package xpf

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
)

func unpackUint8(msg []byte, off int) (i uint8, off1 int, err error) {
	if off+1 > len(msg) {
		return 0, len(msg), &Error{err: "overflow unpacking uint8"}
	}
	return msg[off], off + 1, nil
}

func packUint8(i uint8, msg []byte, off int) (off1 int, err error) {
	if off+1 > len(msg) {
		return len(msg), &Error{err: "overflow packing uint8"}
	}
	msg[off] = i
	return off + 1, nil
}

func unpackDataA(msg []byte, off int) (net.IP, int, error) {
	if off+net.IPv4len > len(msg) {
		return nil, len(msg), &Error{err: "overflow unpacking a"}
	}
	a := append(make(net.IP, 0, net.IPv4len), msg[off:off+net.IPv4len]...)
	off += net.IPv4len
	return a, off, nil
}

func packDataA(a net.IP, msg []byte, off int) (int, error) {
	switch len(a) {
	case net.IPv4len, net.IPv6len:
		// It must be a slice of 4, even if it is 16, we encode only the first 4
		if off+net.IPv4len > len(msg) {
			return len(msg), &Error{err: "overflow packing a"}
		}

		copy(msg[off:], a.To4())
		off += net.IPv4len
	case 0:
		// Allowed, for dynamic updates.
	default:
		return len(msg), &Error{err: "overflow packing a"}
	}
	return off, nil
}

func unpackDataAAAA(msg []byte, off int) (net.IP, int, error) {
	if off+net.IPv6len > len(msg) {
		return nil, len(msg), &Error{err: "overflow unpacking aaaa"}
	}
	aaaa := append(make(net.IP, 0, net.IPv6len), msg[off:off+net.IPv6len]...)
	off += net.IPv6len
	return aaaa, off, nil
}

func packDataAAAA(aaaa net.IP, msg []byte, off int) (int, error) {
	switch len(aaaa) {
	case net.IPv6len:
		if off+net.IPv6len > len(msg) {
			return len(msg), &Error{err: "overflow packing aaaa"}
		}

		copy(msg[off:], aaaa)
		off += net.IPv6len
	case 0:
		// Allowed, dynamic updates.
	default:
		return len(msg), &Error{err: "overflow packing aaaa"}
	}
	return off, nil
}

func unpackUint16(msg []byte, off int) (i uint16, off1 int, err error) {
	if off+2 > len(msg) {
		return 0, len(msg), &Error{err: "overflow unpacking uint16"}
	}
	return binary.BigEndian.Uint16(msg[off:]), off + 2, nil
}

func packUint16(i uint16, msg []byte, off int) (off1 int, err error) {
	if off+2 > len(msg) {
		return len(msg), &Error{err: "overflow packing uint16"}
	}
	binary.BigEndian.PutUint16(msg[off:], i)
	return off + 2, nil
}

func parseIPVersion(s string) (ui uint8, err error) {
	i, err := strconv.Atoi(s)
	if err != nil {
		return ui, err
	}
	if i != 4 && i != 6 {
		return ui, fmt.Errorf("invalid IP version %v", i)
	}
	return uint8(i), nil
}

func parseProtocol(s string) (ui uint8, err error) {
	i, err := strconv.Atoi(s)
	if err != nil {
		return ui, err
	}
	if i != 17 && i != 6 {
		return ui, fmt.Errorf("invalid network protocol %v", i)
	}
	return uint8(i), nil
}

func parseIPAddress(s string, version uint8) (net.IP, error) {
	ip := net.ParseIP(s)
	if ip == nil {
		return ip, fmt.Errorf("failed to translate %v to an IP Address", s)
	}

	switch version {
	case 4:
		if ip.To4() == nil {
			return ip, fmt.Errorf("failed to parse %v as IPV4", ip)
		}
	case 6:
		if ip.To16() == nil {
			return ip, fmt.Errorf("failed to parse %v as IPv6", ip)
		}
	}

	return ip, nil
}

func parsePort(s string) (ui uint16, err error) {
	i, err := strconv.Atoi(s)
	if err != nil {
		return ui, err
	}
	if i <= 0 {
		return ui, fmt.Errorf("invalid port number %v", i)
	}
	return uint16(i), err
}
