package xpf

import (
	"fmt"
	"net"
	"reflect"
	"testing"

	"github.com/coredns/coredns/plugin/test"
	coretest "github.com/coredns/coredns/plugin/test"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	xpf, err := New()
	assert.NotNil(t, xpf)
	assert.NoError(t, err)
}

func TestAppendXpfRecordV4(t *testing.T) {
	testrequest := new(dns.Msg)
	testrequest.SetQuestion("example.org.", dns.TypeA)
	teststate := request.Request{W: &coretest.ResponseWriter{}, Req: testrequest}
	err := appendXpfRecord(&teststate)
	assert.NoError(t, err)
	assert.True(t, containsXpfRR(teststate, XPFPrivateRR{4, 17, net.IPv4(10, 240, 0, 1).To4(), net.IPv4(127, 0, 0, 1).To4(), 40212, 53}), "failed to find an expected XPF Data object in additional section\n")
}

func TestAppendXpfRecordV6(t *testing.T) {
	testrequest := new(dns.Msg)
	testrequest.SetQuestion("example.org.", dns.TypeAAAA)
	teststate := request.Request{W: &coretest.ResponseWriter6{}, Req: testrequest}
	err := appendXpfRecord(&teststate)
	assert.NoError(t, err)
	assert.True(t, containsXpfRR(teststate, XPFPrivateRR{6, 17, net.ParseIP("fe80::42:ff:feca:4c65"), net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 40212, 53}), "failed to find an expected XPF Data object in additional section\n")
}

func BenchmarkAppendXpfRecord(b *testing.B) {
	testrequest := new(dns.Msg)
	testrequest.SetQuestion("example.org.", dns.TypeA)
	teststate := request.Request{W: &test.ResponseWriter{}, Req: testrequest}
	for n := 0; n < b.N; n++ {
		_ = appendXpfRecord(&teststate)
	}
}

func containsXpfRR(req request.Request, expected XPFPrivateRR) bool {
	for _, adds := range req.Req.Extra {
		testPrivateRR := adds.(*dns.PrivateRR)
		if testPrivateRR == nil {
			continue
		}
		testXPFData := testPrivateRR.Data.(*XPFPrivateRR)
		if testXPFData == nil {
			continue
		}
		if reflect.DeepEqual(&expected, testXPFData) {
			return true
		}
		fmt.Printf("expected (%v) != actual (%v)", expected, testXPFData)
	}
	return false
}
