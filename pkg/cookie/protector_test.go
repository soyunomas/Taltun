package cookie

import (
	"net"
	"testing"
)

func TestProtectorCloseIsIdempotent(t *testing.T) {
	p := NewProtector()
	cookie := p.GenerateCookie(net.IPv4(192, 0, 2, 1))
	if !p.ValidateCookie(net.IPv4(192, 0, 2, 1), cookie) {
		t.Fatal("generated cookie did not validate")
	}
	p.Close()
	p.Close()

	select {
	case <-p.done:
	default:
		t.Fatal("protector did not close")
	}
}
