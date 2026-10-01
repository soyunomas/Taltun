package config

import (
	"strings"
	"testing"
)

func TestDecodeKey(t *testing.T) {
	valid := strings.Repeat("ab", keySize)
	got, err := decodeKey(valid)
	if err != nil {
		t.Fatalf("decodeKey(valid): %v", err)
	}
	if len(got) != keySize {
		t.Fatalf("decoded key size = %d, want %d", len(got), keySize)
	}

	if _, err := decodeKey("not-hex"); err == nil {
		t.Fatal("expected malformed hex to fail")
	}
	if _, err := decodeKey(strings.Repeat("00", keySize-1)); err == nil {
		t.Fatal("expected wrong key length to fail")
	}
}

func TestParseLegacyPeerIncludesPinnedPublicKey(t *testing.T) {
	pub := strings.Repeat("11", keySize)
	p := parseLegacyPeer("10.0.0.2,192.0.2.10:9000," + pub)

	if p.VIP != "10.0.0.2" {
		t.Fatalf("VIP = %q", p.VIP)
	}
	if p.Endpoint != "192.0.2.10:9000" {
		t.Fatalf("Endpoint = %q", p.Endpoint)
	}
	if p.PublicKey != pub {
		t.Fatalf("PublicKey = %q", p.PublicKey)
	}
}
