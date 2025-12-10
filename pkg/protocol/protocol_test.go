package protocol

import (
	"testing"
)

// Test funcional básico
func TestEncodeParse(t *testing.T) {
	buf := make([]byte, 1024)
	nonceIn := []byte("123456789012") // 12 bytes
	sessionIDIn := uint32(0xAABBCCDD)

	// 1. Encode
	n, err := EncodeDataHeader(buf, sessionIDIn, nonceIn)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}
	if n != HeaderSize {
		t.Errorf("Expected size %d, got %d", HeaderSize, n)
	}

	// Simular payload
	copy(buf[n:], []byte("PAYLOAD"))
	totalLen := n + 7

	// 2. Parse
	msgType, sessionID, nonceOut, payload, err := ParseHeader(buf[:totalLen])
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if msgType != MsgTypeData {
		t.Errorf("Wrong type: %v", msgType)
	}
	if sessionID != sessionIDIn {
		t.Errorf("Wrong sessionID: %x", sessionID)
	}
	if string(nonceOut) != string(nonceIn) {
		t.Errorf("Wrong nonce")
	}
	if string(payload) != "PAYLOAD" {
		t.Errorf("Wrong payload")
	}
}

// Benchmark de ParseHeader para asegurar Zero-Allocation
func BenchmarkParseHeader(b *testing.B) {
	// Preparar datos simulados
	buf := make([]byte, HeaderSize+100)
	buf[0] = MsgTypeData
	buf[1] = 0xAA
	buf[5] = 0xFF // Inicio Nonce

	b.ResetTimer()
	b.ReportAllocs() // Esto nos dirá si fallamos en la optimización

	for i := 0; i < b.N; i++ {
		// La llamada que queremos medir
		_, _, _, _, _ = ParseHeader(buf)
	}
}

// Benchmark de EncodeDataHeader
func BenchmarkEncodeHeader(b *testing.B) {
	buf := make([]byte, HeaderSize)
	nonce := []byte("123456789012")
	sid := uint32(12345)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = EncodeDataHeader(buf, sid, nonce)
	}
}
