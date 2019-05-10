package xpf

import (
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
