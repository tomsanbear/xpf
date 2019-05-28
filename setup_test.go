package xpf

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/mholt/caddy"
)

func TestSetup(t *testing.T) {
	c := caddy.NewTestController("dns", "xpf")

	err := setup(c)
	assert.NoError(t, err)
}
