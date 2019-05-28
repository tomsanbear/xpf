package xpf

import (
	"strconv"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyfile"
)

// PluginName is the name of our plugin
const PluginName string = "xpf"

func init() {
	caddy.RegisterPlugin(PluginName, caddy.Plugin{
		ServerType: "dns",
		Action:     setup,
	})
}

func setup(c *caddy.Controller) error {

	// Normal Setup
	xpf, err := parseXpf(c)
	if err != nil {
		return plugin.Error(PluginName, err)
	}

	// Pass xpf plugin to our context
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		xpf.Next = next
		return xpf
	})

	// Setup startup and shutdown behaviour
	c.OnStartup(func() error {
		return xpf.OnStartup()
	})
	c.OnShutdown(func() error {
		return xpf.OnShutdown()
	})

	return nil
}

func parseXpf(c *caddy.Controller) (*XPF, error) {
	var (
		x   *XPF
		err error
		i   int
	)

	// Ensure only one block present ever
	for c.Next() {
		if i > 0 {
			return nil, plugin.ErrOnce
		}
		i++
		if len(c.RemainingArgs()) > 0 {
			return x, c.Errf("invalid argument trailing xpf %v", c.RemainingArgs())
		}
		x, err = parseXpfStanza(&c.Dispenser)
		if err != nil {
			return x, err
		}
	}

	return x, nil
}

func parseXpfStanza(c *caddyfile.Dispenser) (*XPF, error) {
	x, err := New()
	if err != nil {
		return x, err
	}

	// xpf stanza if present
	for c.NextBlock() {
		if err := parseXpfBlock(c, x); err != nil {
			return x, err
		}
	}
	return x, nil
}

func parseXpfBlock(c *caddyfile.Dispenser, x *XPF) (err error) {
	switch c.Val() {
	case "rr_type":
		if arg := c.NextArg(); !arg {
			return c.Errf("missing rr_type argument")
		}
		rrtype64, err := strconv.ParseUint(c.Val(), 10, 16)
		if err != nil {
			return c.Errf("failed to parse RR record type: %v", c.Val())
		}
		if rrtype64 < 65280 || rrtype64 > 65534 {
			return c.Errf("invalid private RR record type: %v", c.Val())
		}
		x.rrtype = uint16(rrtype64)
	default:
		return c.Errf("unknown property '%s'", c.Val())
	}
	return nil
}
