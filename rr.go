package xpf

import (
	"fmt"
	"net"

	"github.com/miekg/dns"
)

// XPFPrivateRR type captures the data used to create the XPF record, in the form of a Private RR in CoreDNS
type XPFPrivateRR struct {
	IPVersion   uint8
	Protocol    uint8
	SrcAddress  net.IP
	DestAddress net.IP
	SrcPort     uint16
	DestPort    uint16
}

func NewXPFPrivateRR() dns.PrivateRdata {
	return &XPFPrivateRR{}
}

func (rr *XPFPrivateRR) Len() int {
	var l int
	l++ // IpVersion
	l++ // Protocol
	switch rr.IPVersion {
	case 4:
		l += net.IPv4len // SrcAddr
		l += net.IPv4len // DestAddr

	case 6:
		l += net.IPv6len // SrcAddr
		l += net.IPv6len // DestAddr
	}
	l += 2 // SrcPort
	l += 2 // DestPort
	//
	return l
}

func (rr *XPFPrivateRR) String() string {
	return fmt.Sprintf(";%v %v %v %v", rr.SrcAddress, rr.SrcPort, rr.DestAddress, rr.DestPort)
}

func (rr *XPFPrivateRR) Parse(txt []string) error {
	panic("dns: internal error: parse should never be called on XPF")
}

func (rr *XPFPrivateRR) Pack(msg []byte) (off int, err error) {
	off, err = packUint8(rr.IPVersion, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint8(rr.Protocol, msg, off)
	if err != nil {
		return off, err
	}
	switch rr.IPVersion {
	case 4:
		off, err = packDataA(rr.SrcAddress, msg, off)
		if err != nil {
			return off, err
		}
		off, err = packDataA(rr.DestAddress, msg, off)
		if err != nil {
			return off, err
		}
	case 6:
		off, err = packDataAAAA(rr.SrcAddress, msg, off)
		if err != nil {
			return off, err
		}
		off, err = packDataAAAA(rr.DestAddress, msg, off)
		if err != nil {
			return off, err
		}
	}
	off, err = packUint16(rr.SrcPort, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint16(rr.DestPort, msg, off)
	if err != nil {
		return off, err
	}
	return off, nil
}

func (rr *XPFPrivateRR) Unpack(msg []byte) (off int, err error) {
	rdStart := off
	_ = rdStart

	rr.IPVersion, off, err = unpackUint8(msg, off)
	if err != nil {
		return off, err
	}
	if off == len(msg) {
		return off, nil
	}
	rr.Protocol, off, err = unpackUint8(msg, off)
	if err != nil {
		return off, err
	}
	if off == len(msg) {
		return off, nil
	}
	switch rr.IPVersion {
	case 4:
		rr.SrcAddress, off, err = unpackDataA(msg, off)
		if err != nil {
			return off, err
		}
		if off == len(msg) {
			return off, nil
		}
		rr.DestAddress, off, err = unpackDataA(msg, off)
		if err != nil {
			return off, err
		}
		if off == len(msg) {
			return off, nil
		}
	case 6:
		rr.SrcAddress, off, err = unpackDataAAAA(msg, off)
		if err != nil {
			return off, err
		}
		if off == len(msg) {
			return off, nil
		}
		rr.DestAddress, off, err = unpackDataAAAA(msg, off)
		if err != nil {
			return off, err
		}
		if off == len(msg) {
			return off, nil
		}
	}
	rr.SrcPort, off, err = unpackUint16(msg, off)
	if err != nil {
		return off, err
	}
	if off == len(msg) {
		return off, nil
	}
	rr.DestPort, off, err = unpackUint16(msg, off)
	if err != nil {
		return off, err
	}
	return off, nil
}

func (rr *XPFPrivateRR) Copy(dest dns.PrivateRdata) error {
	xpf, ok := dest.(*XPFPrivateRR)
	if !ok {
		return dns.ErrRdata
	}
	xpf.IPVersion = rr.IPVersion
	xpf.Protocol = rr.Protocol
	xpf.SrcAddress = rr.SrcAddress
	xpf.DestAddress = rr.DestAddress
	xpf.SrcPort = rr.SrcPort
	xpf.DestPort = rr.DestPort
	return nil
}
