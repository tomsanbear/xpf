package xpf

import (
	"fmt"
	"net"
	"reflect"
	"testing"

	"github.com/coredns/coredns/plugin/test"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestAppendXpfRecord(t *testing.T) {
	testrequest := new(dns.Msg)
	testrequest.SetQuestion("example.org.", dns.TypeA)
	teststate := request.Request{W: &test.ResponseWriter{}, Req: testrequest}

	tests := []struct {
		testrecord  request.Request
		expectedXPF XPFPrivateRR
		shouldfail  bool
	}{
		{teststate, XPFPrivateRR{4, 17, net.IPv4(10, 240, 0, 1).To4(), net.IPv4(127, 0, 0, 1).To4(), 40212, 53}, false},
	}

	for _, test := range tests {
		err := appendXpfRecord(&test.testrecord)
		if test.shouldfail {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
			assert.True(t, containsXpfRR(test.testrecord, test.expectedXPF), "failed to find an expected XPF Data object in additional section")
		}
	}
}

func BenchmarkAppendXpfRecord(b *testing.B) {
	testrequest := new(dns.Msg)
	testrequest.SetQuestion("example.org.", dns.TypeA)
	teststate := request.Request{W: &test.ResponseWriter{}, Req: testrequest}
	for n := 0; n < b.N; n++ {
		appendXpfRecord(&teststate)
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
