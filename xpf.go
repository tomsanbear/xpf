package xpf

import (
	"net"
	"strconv"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"golang.org/x/net/context"
)

const TypeXPF uint16 = 65422

// XPF type captures anything needed to append the XPF record to our queries
type XPF struct {
	Next plugin.Handler
}

// New creates a new instance of the XPF type
func New() (*XPF, error) {
	return &XPF{}, nil
}

func (xpf *XPF) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	rrw := dnstest.NewRecorder(w)

	appendXpfRecord(&state)

	rc, err := plugin.NextOrFailure(xpf.Name(), xpf.Next, ctx, rrw, r)
	return rc, err
}

func (xpf *XPF) Name() string { return "xpf" }

// AppendXpfRecord adds the relevant XPF record to the request object
func appendXpfRecord(state *request.Request) error {
	xpfRR := &dns.PrivateRR{}

	xpfRRData := &XPFPrivateRR{}
	if ipVersion := net.ParseIP(state.LocalIP()).To4(); ipVersion != nil {
		xpfRRData.IPVersion = 4
		xpfRRData.SrcAddress = net.ParseIP(state.IP()).To4()
		xpfRRData.DestAddress = net.ParseIP(state.LocalIP()).To4()
	} else if ipVersion := net.ParseIP(state.LocalIP()).To16(); ipVersion != nil {
		xpfRRData.IPVersion = 6
		xpfRRData.SrcAddress = net.ParseIP(state.IP()).To16()
		xpfRRData.DestAddress = net.ParseIP(state.LocalIP()).To16()
	}
	srcPort64, err := strconv.ParseUint(state.Port(), 16, 16)
	if err != nil {
		// TODO: Handle it
	}
	xpfRRData.SrcPort = uint16(srcPort64)
	destPort64, err := strconv.ParseUint(state.LocalPort(), 16, 16)
	if err != nil {
		// TODO: Handle it
	}
	xpfRRData.DestPort = uint16(destPort64)
	xpfRRData.Protocol = protoIANA(state.Proto())

	// Put the data into the PrivateRR
	xpfRR.Data = xpfRRData

	xpfRR.Hdr = dns.RR_Header{
		Name:   ".",
		Rrtype: TypeXPF,
		Class:  1,
		Ttl:    0,
	}

	// Append to the Additional Section
	state.Req.Extra = append(state.Req.Extra, xpfRR)

	return nil
}

func protoIANA(proto string) uint8 {
	switch proto {
	case "udp":
		return 17
	case "tcp":
		return 6
	}
	return 17 // TODO: should error here?
}
