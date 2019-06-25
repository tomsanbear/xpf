package xpf

import (
	"fmt"
	"net"
	"strconv"

	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"golang.org/x/net/context"
)

var log = clog.NewWithPlugin("xpf")

// DefaultTypeXPF uses the default rrtype used in wireshark
const DefaultTypeXPF uint16 = 65422

// XPF type captures anything needed to append the XPF record to our queries
type XPF struct {
	rrtype uint16

	Next plugin.Handler
}

// New creates a new instance of the XPF type
func New() (*XPF, error) {
	return &XPF{rrtype: DefaultTypeXPF}, nil
}

// ServeDNS is the handler provided by the CaddyServer we are implementing
func (xpf *XPF) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (rc int, err error) {
	state := request.Request{W: w, Req: r}

	err = appendXpfRecord(xpf.rrtype, &state)
	if err != nil {
		log.Errorf("xpf append failed with: %v", err)
		return rc, &Error{"failed to append the XPF record to the DNS request"}
	}

	rc, err = plugin.NextOrFailure(xpf.Name(), xpf.Next, ctx, w, r)
	return rc, err
}

// Name is the name of the plugin
func (xpf *XPF) Name() string { return "xpf" }

// AppendXpfRecord adds the relevant XPF record to the request object
func appendXpfRecord(rrtype uint16, state *request.Request) error {
	xpfRR := &dns.PrivateRR{}

	xpfRRData := &XPFPrivateRR{}
	switch state.Family() {
	case 1:
		xpfRRData.IPVersion = 4
		xpfRRData.SrcAddress = net.ParseIP(state.IP()).To4()
		xpfRRData.DestAddress = net.ParseIP(state.LocalIP()).To4()
	case 2:
		xpfRRData.IPVersion = 6
		xpfRRData.SrcAddress = net.ParseIP(state.IP()).To16()
		xpfRRData.DestAddress = net.ParseIP(state.LocalIP()).To16()
	}
	srcPort64, err := strconv.ParseUint(state.Port(), 10, 16)
	if err != nil {
		return err
	}
	xpfRRData.SrcPort = uint16(srcPort64)
	if xpfRRData.SrcPort == 0 {
		return fmt.Errorf("source Port is missing")
	}
	destPort64, err := strconv.ParseUint(state.LocalPort(), 10, 16)
	if err != nil {
		return err
	}
	xpfRRData.DestPort = uint16(destPort64)
	if xpfRRData.DestPort == 0 {
		return fmt.Errorf("dest Port is missing")
	}
	xpfRRData.Protocol, err = protoIANA(state.Proto())
	if err != nil {
		return err
	}

	// Put the data into the PrivateRR
	xpfRR.Data = xpfRRData

	xpfRR.Hdr = dns.RR_Header{
		Name:   ".",
		Rrtype: rrtype,
		Class:  1,
		Ttl:    0,
	}

	// Append to the Additional Section
	state.Req.Extra = append(state.Req.Extra, xpfRR)

	return nil
}

func protoIANA(proto string) (uint8, error) {
	switch proto {
	case "udp":
		return 17, nil
	case "tcp":
		return 6, nil
	}
	return 0, fmt.Errorf("invalid network protocol: %v", proto)
}

// OnStartup handles any plugin specific startup logic
func (xpf *XPF) OnStartup() (err error) {
	// Setup up the new record type
	log.Infof("Registered new XPF RR with type code: %v", xpf.rrtype)
	dns.PrivateHandle("XPF", xpf.rrtype, NewXPFPrivateRR)
	return nil
}

// OnShutdown handles any plugin specific startup logic
func (xpf *XPF) OnShutdown() (err error) {
	dns.PrivateHandleRemove(xpf.rrtype)
	return nil
}
