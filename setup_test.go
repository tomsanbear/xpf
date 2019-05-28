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
	}

	for _, test := range tests {
		c := caddy.NewTestController("dns", test.input)
		x, err := parseXpf(c)
		if test.shouldErr {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
			assert.Equal(t, test.expRRType, x.rrtype)
		}
	}
}
