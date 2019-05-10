package xpf

import (
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/mholt/caddy"
	"github.com/miekg/dns"
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
	x, err := New()
	if err != nil {
		return x, err
	}
	return x, nil
}

// OnStartup handles any plugin specific startup logic
func (x *XPF) OnStartup() (err error) {
	// Setup up the new record type
	dns.PrivateHandle("XPF", TypeXPF, NewXPFPrivateRR)
	return nil
}

// OnShutdown handles any plugin specific startup logic
func (x *XPF) OnShutdown() (err error) {
	dns.PrivateHandleRemove(TypeXPF)
	return nil
}
