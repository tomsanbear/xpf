package xpf

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUint8(t *testing.T) {
	tests := []struct {
		item      uint8
		shouldErr bool
	}{
		{8, false},
	}

	for _, test := range tests {
		msg := make([]byte, 1)
		_, err := packUint8(test.item, msg, 0)
		if test.shouldErr {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
		}

		unpacked, _, err := unpackUint8(msg, 0)
		if test.shouldErr {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
			assert.Equal(t, test.item, unpacked)
		}
	}
}

func TestUint16(t *testing.T) {
	tests := []struct {
		item      uint16
		shouldErr bool
	}{
		{8, false},
	}

	for _, test := range tests {
		msg := make([]byte, 2)
		_, err := packUint16(test.item, msg, 0)
		if test.shouldErr {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
		}

		unpacked, _, err := unpackUint16(msg, 0)
		if test.shouldErr {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
			assert.Equal(t, test.item, unpacked)
		}
	}
}

func TestParsePort(t *testing.T) {
	tests := []struct {
		port      string
		expected  uint16
		shouldErr bool
	}{
		{"53", 53, false},
		{"0", 0, false}, // Enforcing this case here for sanity
		{"-1", 0, true},
		{"65536", 0, true},
		{"", 0, true},
	}
	for _, test := range tests {
		port, err := parsePort(test.port)
		if test.shouldErr {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
			assert.Equal(t, test.expected, port)
		}
	}
}
