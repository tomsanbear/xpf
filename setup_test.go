package xpf

import (
	"testing"

	"github.com/mholt/caddy"

	"github.com/stretchr/testify/assert"
)

func TestSetup(t *testing.T) {

	tests := []struct {
		input     string
		shouldErr bool
		expRRType uint16
	}{
		// positive
		{`xpf {
			rr_type 65423
		}`, false, uint16(65423)},
		{`xpf`, false, uint16(65422)},
		// negative
		{`xpf {
			rr_type
		}`, true, uint16(0)},
		{`xpf {
			unknown_opt 45
		}`, true, uint16(0)},
		{`xpf {
			rr_type 65279
		}`, true, uint16(0)},
		{`xpf {
			rr_type 65535
		}`, true, uint16(0)},
		{`xpf meow`, true, uint16(0)},
		{`xpf {
			rr_type 65535
		}
		xpf {
			rr_type 65535
		}`, true, uint16(0)},
	}

	for i, test := range tests {
		c := caddy.NewTestController("dns", test.input)
		x, err := parseXpf(c)
		if test.shouldErr {
			assert.Error(t, err, i)
		} else {
			assert.NoError(t, err, i)
			assert.Equal(t, test.expRRType, x.rrtype, i)
		}
	}
}
