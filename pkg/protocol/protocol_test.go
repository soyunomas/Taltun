package protocol

import (
	"bytes"
	"testing"
)

func TestEncodeParseDataHeader(t *testing.T) {
	buf := make([]byte, HeaderSize+7)
	nonceIn := []byte("123456789012")
	senderVIP := uint32(0x0a000002)
	sessionID := uint64(0x0102030405060708)

	n, err := EncodeDataHeader(buf, senderVIP, sessionID, nonceIn)
	if err != nil {
		t.Fatalf("EncodeDataHeader: %v", err)
	}
	copy(buf[n:], []byte("PAYLOAD"))

	msgType, gotVIP, gotSession, nonceOut, payload, err := ParseHeader(buf)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if msgType != MsgTypeData {
		t.Fatalf("type = %d", msgType)
	}
	if gotVIP != senderVIP {
		t.Fatalf("VIP = %x, want %x", gotVIP, senderVIP)
	}
	if gotSession != sessionID {
		t.Fatalf("session = %x, want %x", gotSession, sessionID)
	}
	if !bytes.Equal(nonceOut, nonceIn) {
		t.Fatal("nonce mismatch")
	}
	if string(payload) != "PAYLOAD" {
		t.Fatalf("payload = %q", payload)
	}
}

func TestDataHeaderRejectsZeroSession(t *testing.T) {
	buf := make([]byte, HeaderSize)
	if _, err := EncodeDataHeader(buf, 1, 0, make([]byte, NonceSize)); err == nil {
		t.Fatal("expected zero session id to be rejected")
	}
}

func TestHandshakeRoundTrip(t *testing.T) {
	buf := make([]byte, 256)
	staticPub := make([]byte, 32)
	ephemeral := make([]byte, 32)
	auth := make([]byte, AuthTagSize)
	cookie := make([]byte, CookieSize)
	for i := range staticPub {
		staticPub[i] = byte(i + 1)
		ephemeral[i] = byte(0x80 + i)
		auth[i] = byte(0xa0 + i%16)
	}
	for i := range cookie {
		cookie[i] = byte(0x10 + i)
	}

	sessionID := uint64(0x0102030405060708)
	n, err := EncodeHandshake(
		buf,
		MsgTypeHandshakeInit,
		0x0a000002,
		sessionID,
		staticPub,
		ephemeral,
		auth,
		cookie,
	)
	if err != nil {
		t.Fatalf("EncodeHandshake: %v", err)
	}

	h, err := ParseHandshake(buf[:n])
	if err != nil {
		t.Fatalf("ParseHandshake: %v", err)
	}
	if h.Type != MsgTypeHandshakeInit || h.SenderVIP != 0x0a000002 || h.SessionID != sessionID {
		t.Fatalf("unexpected handshake header: %+v", h)
	}
	if !bytes.Equal(h.StaticPublic, staticPub) ||
		!bytes.Equal(h.Ephemeral, ephemeral) ||
		!bytes.Equal(h.AuthTag, auth) ||
		!bytes.Equal(h.Cookie, cookie) {
		t.Fatal("handshake payload mismatch")
	}
}

func TestHandshakeFinishRoundTrip(t *testing.T) {
	buf := make([]byte, HandshakeFinishSize)
	auth := bytes.Repeat([]byte{0x42}, AuthTagSize)
	sessionID := uint64(99)

	n, err := EncodeHandshakeFinish(buf, 0x0a000002, sessionID, auth)
	if err != nil {
		t.Fatal(err)
	}
	vip, gotSession, gotAuth, err := ParseHandshakeFinish(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	if vip != 0x0a000002 || gotSession != sessionID || !bytes.Equal(gotAuth, auth) {
		t.Fatal("finish round-trip mismatch")
	}
}

func TestLegacyHandshakeIsRejected(t *testing.T) {
	buf := make([]byte, 69)
	buf[0] = MsgTypeHandshakeInit
	if _, err := ParseHandshake(buf); err == nil {
		t.Fatal("expected v1 handshake to be rejected")
	}
}

func BenchmarkParseHeader(b *testing.B) {
	buf := make([]byte, HeaderSize+100)
	nonce := make([]byte, NonceSize)
	if _, err := EncodeDataHeader(buf, 1, 1, nonce); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _, _, _, _ = ParseHeader(buf)
	}
}

func BenchmarkEncodeHeader(b *testing.B) {
	buf := make([]byte, HeaderSize)
	nonce := []byte("123456789012")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = EncodeDataHeader(buf, 1, 1, nonce)
	}
}
