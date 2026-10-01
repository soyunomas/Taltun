package router

import (
	"net"
	"sync"
	"testing"

	"github.com/Soyunomas/taltun/internal/session"
	"github.com/Soyunomas/taltun/pkg/netutil"
)

func peer(vip byte) *session.Peer {
	var key [32]byte
	return session.NewPeer(netutil.IPToUint32(net.IPv4(10, 0, 0, vip)), nil, key)
}

func TestExactIPv4LongestPrefixMatch(t *testing.T) {
	r := New()
	p20 := peer(1)
	p22 := peer(2)
	p23 := peer(3)
	p31 := peer(4)
	p32 := peer(5)

	for cidr, p := range map[string]*session.Peer{
		"10.8.0.0/20":   p20,
		"10.8.4.0/22":   p22,
		"10.8.6.0/23":   p23,
		"10.8.7.10/31":  p31,
		"10.8.7.11/32":  p32,
	} {
		if err := r.Insert(cidr, p); err != nil {
			t.Fatalf("insert %s: %v", cidr, err)
		}
	}

	cases := []struct {
		ip   string
		want *session.Peer
	}{
		{"10.8.1.1", p20},
		{"10.8.4.1", p22},
		{"10.8.6.1", p23},
		{"10.8.7.10", p31},
		{"10.8.7.11", p32},
	}
	for _, tc := range cases {
		if got := r.Lookup(netutil.IPToUint32(net.ParseIP(tc.ip))); got != tc.want {
			t.Fatalf("lookup %s got %p want %p", tc.ip, got, tc.want)
		}
	}
}

func TestConcurrentInsertAndLookup(t *testing.T) {
	r := New()
	base := peer(1)
	if err := r.Insert("10.0.0.0/8", base); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				_ = r.Lookup(uint32(0x0a000000 + i))
			}
		}(worker)
	}
	for i := 0; i < 100; i++ {
		p := peer(byte((i % 250) + 1))
		if err := r.Insert("10.1.0.0/16", p); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
}

func TestRejectsIPv6Route(t *testing.T) {
	if err := New().Insert("2001:db8::/32", peer(1)); err == nil {
		t.Fatal("expected IPv6 route to be rejected")
	}
}
