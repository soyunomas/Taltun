package crypto

import (
	"bytes"
	"testing"
)

func TestKeyExchangeAndDerivation(t *testing.T) {
	alice, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	bob, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	aliceShared, err := alice.SharedSecret(bob.Public[:])
	if err != nil {
		t.Fatal(err)
	}
	bobShared, err := bob.SharedSecret(alice.Public[:])
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(aliceShared[:], bobShared[:]) {
		t.Fatalf("ECDH mismatch\nAlice: %x\nBob:   %x", aliceShared, bobShared)
	}

	aliceAEAD, err := DeriveSessionKey(aliceShared, "test-context")
	if err != nil {
		t.Fatal(err)
	}
	bobAEAD, err := DeriveSessionKey(bobShared, "test-context")
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("Attack at dawn!")
	nonce := make([]byte, aliceAEAD.NonceSize())

	encrypted := aliceAEAD.Seal(nil, nonce, msg, nil)
	decrypted, err := bobAEAD.Open(nil, nonce, encrypted, nil)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}
	if !bytes.Equal(decrypted, msg) {
		t.Errorf("message corrupted: got %q, want %q", decrypted, msg)
	}
}

func TestSharedSecretRejectsLowOrderPublicKey(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	lowOrder := make([]byte, KeySize)
	if _, err := kp.SharedSecret(lowOrder); err == nil {
		t.Fatal("expected X25519 to reject a low-order public key")
	}
}

func TestSharedSecretRejectsWrongKeySize(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := kp.SharedSecret(make([]byte, KeySize-1)); err == nil {
		t.Fatal("expected invalid peer key size to be rejected")
	}
}
