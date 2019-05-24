package xpf

import (
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestParseXPF(t *testing.T) {
	tests := []struct {
		testrecord string
		shouldErr  bool
	}{
		{strings.Join([]string{".", "0", "IN", "XPF", "4", "17", "1.2.3.4", "5.6.7.8", "1000", "1001"}, "\t"), false},
		{strings.Join([]string{".", "0", "IN", "XPF", "6", "6", "2001:db8::aaaa:0:0:1", "2001:db8::aaaa:0:0:1", "1000", "1001"}, "\t"), false},
		{strings.Join([]string{".", "0", "IN", "XPF", "4", "17", "a_very_short_record"}, "\t"), true},
		{strings.Join([]string{".", "0", "IN", "XPF", "4", "17", "meow", "5.6.7.8", "1000", "1001"}, "\t"), true},
		{strings.Join([]string{".", "0", "IN", "XPF", "4", "17", "1.2.3.4", "5.6.7.8", "not an int", "1001"}, "\t"), true},
		{strings.Join([]string{".", "0", "IN", "XPF", "7", "17", "1.2.3.4", "5.6.7.8", "1000", "1001"}, "\t"), true},
		{strings.Join([]string{".", "0", "IN", "XPF", "4", "18", "1.2.3.4", "5.6.7.8", "1000", "1001"}, "\t"), true},
	}

	dns.PrivateHandle("XPF", TypeXPF, NewXPFPrivateRR)
	defer dns.PrivateHandleRemove(TypeXPF)

	for _, test := range tests {
		rr, err := dns.NewRR(test.testrecord)
		if err != nil && !test.shouldErr {
			t.Fatal(err)
		}
		if test.shouldErr {
			assert.Error(t, err)
		} else {
			assert.Equal(t, rr.String(), test.testrecord)
		}
	}
}

func TestPackXPF(t *testing.T) {
	testsV4 := []struct {
		testrecord XPFPrivateRR
		shouldErr  bool
	}{
		{XPFPrivateRR{4, 16, net.IPv4(1, 2, 3, 4).To4(), net.IPv4(1, 2, 3, 4).To4(), 53, 533}, false},
	}

	for _, test := range testsV4 {
		msgPacked := make([]byte, 14)
		_, err := test.testrecord.Pack(msgPacked)
		if test.shouldErr {
			assert.Error(t, err)
		} else {
			assert.Nil(t, err)
		}

		var msgUnpacked XPFPrivateRR
		_, err = msgUnpacked.Unpack(msgPacked)
		if test.shouldErr {
			assert.Error(t, err)
		} else {
			assert.Nil(t, err)
			assert.Equal(t, test.testrecord, msgUnpacked)
		}
	}

	testsV6 := []struct {
		testrecord XPFPrivateRR
		shouldErr  bool
	}{
		{XPFPrivateRR{6, 16, net.IP{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}.To16(), net.IP{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}.To16(), 53, 533}, false},
	}

	for _, test := range testsV6 {
		msgPacked := make([]byte, 38)
		_, err := test.testrecord.Pack(msgPacked)
		if test.shouldErr {
			assert.Error(t, err)
		} else {
			assert.Nil(t, err)
		}

		var msgUnpacked XPFPrivateRR
		_, err = msgUnpacked.Unpack(msgPacked)
		if test.shouldErr {
			assert.Error(t, err)
		} else {
			assert.Nil(t, err)
			assert.Equal(t, test.testrecord, msgUnpacked)
		}
	}
}

func TestLenXPF(t *testing.T) {
	tests := []struct {
		rr          XPFPrivateRR
		expectedLen int
	}{
		{XPFPrivateRR{4, 16, net.IPv4(1, 2, 3, 4).To4(), net.IPv4(1, 2, 3, 4).To4(), 53, 533}, 14},
		{XPFPrivateRR{6, 16, net.IP{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}.To16(), net.IP{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}.To16(), 53, 533}, 38},
	}

	for _, test := range tests {
		assert.Equal(t, test.expectedLen, test.rr.Len())
	}
}

func TestCopyXPF(t *testing.T) {
	tests := []struct {
		rr XPFPrivateRR
	}{
		{XPFPrivateRR{4, 16, net.IPv4(1, 2, 3, 4).To4(), net.IPv4(1, 2, 3, 4).To4(), 53, 533}},
		{XPFPrivateRR{6, 16, net.IP{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}.To16(), net.IP{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}.To16(), 53, 533}},
	}

	for _, test := range tests {
		actual := new(XPFPrivateRR)
		_ = test.rr.Copy(actual)
		assert.Equal(t, &test.rr, actual)
	}
}
