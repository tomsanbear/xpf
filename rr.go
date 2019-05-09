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
	// TODO:
}

func (rr *XPFPrivateRR) Pack(buf []byte) (int, error) {
	// TODO:
}

func (rr *XPFPrivateRR) Unpack(buf []byte) (int, error) {
	// TODO:
}

func (rr *XPFPrivateRR) Copy(dest dns.PrivateRdata) error {
	// TODO:
}
