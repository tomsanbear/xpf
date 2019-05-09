package xpf

import (
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/mholt/caddy"
)

var log = clog.NewWithPlugin("forward")

func init() {
	caddy.RegisterPlugin("xpf", caddy.Plugin{
		ServerType: "dns",
		Action:     setup,
	})
}

func setup(c *caddy.Controller) error {
	xpf, err := parseXpf(c)
	if err != nil {
		return plugin.Error("xpf", err)
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		xpf.Next = next
		return xpf
	})

	return nil
}

func parseXpf(c *caddy.Controller) (*XPF, error) {
	x, err := New()
	if err != nil {
		return x, err
	}
	return x, nil
}
