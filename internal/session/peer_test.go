package session

import (
	"encoding/binary"
	"testing"

	tcrypto "github.com/Soyunomas/taltun/pkg/crypto"
	"github.com/Soyunomas/taltun/pkg/protocol"
)

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

func TestSessionCountersRestartOnlyWithNewSession(t *testing.T) {
	var public [tcrypto.KeySize]byte
	p := NewPeer(1, nil, public)

	eph, err := tcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	p.BeginInitiatorHandshake(10, eph)

	var tx1, rx1 [tcrypto.KeySize]byte
	tx1[0] = 1
	rx1[0] = 2
	if err := p.CompleteInitiatorHandshake(10, tx1, rx1); err != nil {
		t.Fatal(err)
	}

	sessionID, _, counter, ok := p.NextOutbound()
	if !ok || sessionID != 10 || counter != 1 {
		t.Fatalf("first outbound = session %d counter %d ok=%v", sessionID, counter, ok)
	}
	_, _, counter, _ = p.NextOutbound()
	if counter != 2 {
		t.Fatalf("second counter = %d, want 2", counter)
	}

	eph2, err := tcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	p.BeginInitiatorHandshake(11, eph2)
	var tx2, rx2 [tcrypto.KeySize]byte
	tx2[0] = 3
	rx2[0] = 4
	if err := p.CompleteInitiatorHandshake(11, tx2, rx2); err != nil {
		t.Fatal(err)
	}

	sessionID, _, counter, ok = p.NextOutbound()
	if !ok || sessionID != 11 || counter != 1 {
		t.Fatalf("new session first outbound = session %d counter %d ok=%v", sessionID, counter, ok)
	}
}

func TestReplayWindowIsScopedPerSessionAndPreviousExpires(t *testing.T) {
	var public [tcrypto.KeySize]byte
	p := NewPeer(1, nil, public)

	var tx1, rx1 [tcrypto.KeySize]byte
	tx1[0] = 1
	rx1[0] = 2
	eph1, _ := tcrypto.GenerateKeyPair()
	p.BeginInitiatorHandshake(100, eph1)
	if err := p.CompleteInitiatorHandshake(100, tx1, rx1); err != nil {
		t.Fatal(err)
	}

	cipher1, err := tcrypto.NewAEAD(rx1)
	if err != nil {
		t.Fatal(err)
	}
	nonce1 := makeNonce(1)
	ciphertext1 := cipher1.Seal(nil, nonce1, []byte("session-1"), nil)

	if _, err := p.Open(100, nil, nonce1, ciphertext1, nil, 1); err != nil {
		t.Fatalf("first packet rejected: %v", err)
	}
	if _, err := p.Open(100, nil, nonce1, ciphertext1, nil, 1); err == nil {
		t.Fatal("duplicate packet in same session accepted")
	}

	var tx2, rx2 [tcrypto.KeySize]byte
	tx2[0] = 3
	rx2[0] = 4
	eph2, _ := tcrypto.GenerateKeyPair()
	p.BeginInitiatorHandshake(101, eph2)
	if err := p.CompleteInitiatorHandshake(101, tx2, rx2); err != nil {
		t.Fatal(err)
	}

	cipher2, err := tcrypto.NewAEAD(rx2)
	if err != nil {
		t.Fatal(err)
	}
	nonceNew := makeNonce(1)
	ciphertextNew := cipher2.Seal(nil, nonceNew, []byte("session-2"), nil)
	if _, err := p.Open(101, nil, nonceNew, ciphertextNew, nil, 1); err != nil {
		t.Fatalf("counter reset under fresh session rejected: %v", err)
	}

	nonceOld2 := makeNonce(2)
	ciphertextOld2 := cipher1.Seal(nil, nonceOld2, []byte("late-session-1"), nil)
	if _, err := p.Open(100, nil, nonceOld2, ciphertextOld2, nil, 2); err != nil {
		t.Fatalf("valid packet under previous session grace rejected: %v", err)
	}

	if p.PreviousSessionID() != 100 {
		t.Fatalf("previous session = %d, want 100", p.PreviousSessionID())
	}
	p.ExpirePreviousForTest()
	if p.PreviousSessionID() != 0 {
		t.Fatal("previous session did not expire")
	}
	if _, err := p.Open(100, nil, nonceOld2, ciphertextOld2, nil, 2); err == nil {
		t.Fatal("expired previous session accepted a packet")
	}
}

func TestDataHeaderAADPreventsSessionHeaderTampering(t *testing.T) {
	var public [tcrypto.KeySize]byte
	p := NewPeer(1, nil, public)

	var tx, rx [tcrypto.KeySize]byte
	tx[0] = 1
	rx[0] = 2
	eph, _ := tcrypto.GenerateKeyPair()
	p.BeginInitiatorHandshake(222, eph)
	if err := p.CompleteInitiatorHandshake(222, tx, rx); err != nil {
		t.Fatal(err)
	}

	rxAEAD, err := tcrypto.NewAEAD(rx)
	if err != nil {
		t.Fatal(err)
	}
	nonce := makeNonce(1)
	header := make([]byte, protocol.HeaderSize)
	if _, err := protocol.EncodeDataHeader(header, 9, 222, nonce); err != nil {
		t.Fatal(err)
	}
	ciphertext := rxAEAD.Seal(nil, nonce, []byte("payload"), header)

	tampered := append([]byte(nil), header...)
	tampered[4] ^= 1
	if _, err := p.Open(222, nil, nonce, ciphertext, tampered, 1); err == nil {
		t.Fatal("tampered authenticated header was accepted")
	}
}

func makeNonce(counter uint64) []byte {
	nonce := make([]byte, protocol.NonceSize)
	binary.BigEndian.PutUint64(nonce[4:], counter)
	return nonce
}
