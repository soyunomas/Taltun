package session

import (
	"encoding/binary"
	"testing"

	tcrypto "github.com/Soyunomas/taltun/pkg/crypto"
	"github.com/Soyunomas/taltun/pkg/protocol"
)

func BenchmarkSessionSeal(b *testing.B) {
	var public [tcrypto.KeySize]byte
	p := NewPeer(1, nil, public)
	var tx, rx [tcrypto.KeySize]byte
	tx[0] = 1
	rx[0] = 2
	eph, _ := tcrypto.GenerateKeyPair()
	p.BeginInitiatorHandshake(1, eph)
	if err := p.CompleteInitiatorHandshake(1, tx, rx); err != nil {
		b.Fatal(err)
	}

	payload := make([]byte, 1380)
	out := make([]byte, protocol.HeaderSize+len(payload)+16)
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		sessionID, aead, counter, ok := p.NextOutbound()
		if !ok {
			b.Fatal("no outbound session")
		}
		var nonce [protocol.NonceSize]byte
		binary.BigEndian.PutUint64(nonce[4:], counter)
		if _, err := protocol.EncodeDataHeader(out[:protocol.HeaderSize], 1, sessionID, nonce[:]); err != nil {
			b.Fatal(err)
		}
		copy(out[protocol.HeaderSize:], payload)
		_ = aead.Seal(
			out[protocol.HeaderSize:protocol.HeaderSize],
			nonce[:],
			out[protocol.HeaderSize:protocol.HeaderSize+len(payload)],
			out[:protocol.HeaderSize],
		)
	}
}

func BenchmarkSessionOpen(b *testing.B) {
	var public [tcrypto.KeySize]byte
	p := NewPeer(1, nil, public)
	var tx, rx [tcrypto.KeySize]byte
	tx[0] = 1
	rx[0] = 2
	eph, _ := tcrypto.GenerateKeyPair()
	p.BeginInitiatorHandshake(1, eph)
	if err := p.CompleteInitiatorHandshake(1, tx, rx); err != nil {
		b.Fatal(err)
	}

	rxAEAD, _ := tcrypto.NewAEAD(rx)
	payload := make([]byte, 1380)
	header := make([]byte, protocol.HeaderSize)
	ciphertext := make([]byte, 0, len(payload)+rxAEAD.Overhead())
	dst := make([]byte, 0, len(payload))

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		counter := uint64(i + 1)
		var nonce [protocol.NonceSize]byte
		binary.BigEndian.PutUint64(nonce[4:], counter)
		if _, err := protocol.EncodeDataHeader(header, 2, 1, nonce[:]); err != nil {
			b.Fatal(err)
		}
		ciphertext = rxAEAD.Seal(ciphertext[:0], nonce[:], payload, header)
		if _, err := p.Open(1, dst[:0], nonce[:], ciphertext, header, counter); err != nil {
			b.Fatal(err)
		}
	}
}
