package session

import "testing"

func TestPeerMatchesPinnedPublicKey(t *testing.T) {
	var pinned [32]byte
	for i := range pinned {
		pinned[i] = byte(i + 1)
	}

	p := NewPeer(1, nil, pinned)

	if !p.MatchesPublicKey(pinned[:]) {
		t.Fatal("expected configured public key to match")
	}

	other := pinned
	other[0] ^= 0xff
	if p.MatchesPublicKey(other[:]) {
		t.Fatal("expected different public key to be rejected")
	}

	if p.MatchesPublicKey(pinned[:31]) {
		t.Fatal("expected wrong-sized public key to be rejected")
	}
}
