package xpf

import (
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"golang.org/x/net/context"
)

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

}

// AppendXpfRecord adds the relevant XPF record to the request object
func appendXpfRecord(*request.Request) error {
	return nil
}
