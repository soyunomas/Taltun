package protocol

import (
	"bytes"
	"net"
	"testing"
)

func TestPeerUpdatePayloadRoundTrip(t *testing.T) {
	buf := make([]byte, PeerUpdatePayloadSize)
	addr := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 51820}

	n, err := EncodePeerUpdatePayload(buf, 0x0a000002, addr)
	if err != nil {
		t.Fatal(err)
	}
	vip, got, err := ParsePeerUpdatePayload(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	if vip != 0x0a000002 || !got.IP.Equal(addr.IP) || got.Port != addr.Port {
		t.Fatalf("round trip mismatch: vip=%x addr=%v", vip, got)
	}
}

func TestControlHeaderRoundTrip(t *testing.T) {
	buf := make([]byte, HeaderSize+3)
	nonce := bytes.Repeat([]byte{0x42}, NonceSize)
	if _, err := EncodeControlHeader(buf, MsgTypePeerUpdate, 7, 99, nonce); err != nil {
		t.Fatal(err)
	}
	copy(buf[HeaderSize:], []byte{1, 2, 3})

	typ, vip, sessionID, gotNonce, payload, err := ParseControlHeader(buf)
	if err != nil {
		t.Fatal(err)
	}
	if typ != MsgTypePeerUpdate || vip != 7 || sessionID != 99 {
		t.Fatalf("unexpected header: %d %d %d", typ, vip, sessionID)
	}
	if !bytes.Equal(gotNonce, nonce) || !bytes.Equal(payload, []byte{1, 2, 3}) {
		t.Fatal("control header payload mismatch")
	}
}
