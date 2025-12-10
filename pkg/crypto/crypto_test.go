package crypto

import (
	"bytes"
	"testing"
)

func TestKeyExchangeAndDerivation(t *testing.T) {
	// 1. Simular Alice y Bob
	alice, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	bob, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// 2. Intercambio ECDH (Alice calcula secreto con pública de Bob)
	aliceShared, err := alice.SharedSecret(bob.Public[:])
	if err != nil {
		t.Fatal(err)
	}

	// 3. Intercambio ECDH (Bob calcula secreto con pública de Alice)
	bobShared, err := bob.SharedSecret(alice.Public[:])
	if err != nil {
		t.Fatal(err)
	}

	// El secreto ECDH debe ser idéntico
	if !bytes.Equal(aliceShared[:], bobShared[:]) {
		t.Fatalf("ECDH Mismatch!\nAlice: %x\nBob:   %x", aliceShared, bobShared)
	}

	// 4. Derivación de clave de sesión (KDF)
	aliceAEAD, err := DeriveSessionKey(aliceShared, "test-context")
	if err != nil {
		t.Fatal(err)
	}
	bobAEAD, err := DeriveSessionKey(bobShared, "test-context")
	if err != nil {
		t.Fatal(err)
	}

	// 5. Probar encriptación/desencriptación real
	msg := []byte("Attack at dawn!")
	nonce := make([]byte, aliceAEAD.NonceSize()) // Zero nonce for test
	
	encrypted := aliceAEAD.Seal(nil, nonce, msg, nil)
	decrypted, err := bobAEAD.Open(nil, nonce, encrypted, nil)
	
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if string(decrypted) != string(msg) {
		t.Errorf("Message corrupted: got %s, want %s", decrypted, msg)
	}
}
