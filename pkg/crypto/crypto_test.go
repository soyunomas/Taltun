package crypto

import (
	"bytes"
	"testing"
)

func TestKeyExchange(t *testing.T) {
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
		t.Fatal("X25519 shared secrets differ")
	}
}

func TestSharedSecretRejectsLowOrderPublicKey(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kp.SharedSecret(make([]byte, KeySize)); err == nil {
		t.Fatal("expected low-order public key rejection")
	}
}

func TestSharedSecretRejectsWrongKeySize(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kp.SharedSecret(make([]byte, KeySize-1)); err == nil {
		t.Fatal("expected invalid peer key size rejection")
	}
}

func TestSessionKeyDerivationIsDirectionalAndFresh(t *testing.T) {
	aliceStatic, _ := GenerateKeyPair()
	bobStatic, _ := GenerateKeyPair()
	aliceEph1, _ := GenerateKeyPair()
	bobEph1, _ := GenerateKeyPair()

	staticAB, err := aliceStatic.SharedSecret(bobStatic.Public[:])
	if err != nil {
		t.Fatal(err)
	}
	staticBA, err := bobStatic.SharedSecret(aliceStatic.Public[:])
	if err != nil {
		t.Fatal(err)
	}
	ephAB, err := aliceEph1.SharedSecret(bobEph1.Public[:])
	if err != nil {
		t.Fatal(err)
	}
	ephBA, err := bobEph1.SharedSecret(aliceEph1.Public[:])
	if err != nil {
		t.Fatal(err)
	}

	keysA, err := DeriveSessionKeys(
		staticAB, ephAB, 1001, 1, 2,
		aliceStatic.Public[:], bobStatic.Public[:],
		aliceEph1.Public[:], bobEph1.Public[:],
	)
	if err != nil {
		t.Fatal(err)
	}
	keysB, err := DeriveSessionKeys(
		staticBA, ephBA, 1001, 1, 2,
		aliceStatic.Public[:], bobStatic.Public[:],
		aliceEph1.Public[:], bobEph1.Public[:],
	)
	if err != nil {
		t.Fatal(err)
	}

	if keysA != keysB {
		t.Fatal("both peers must derive identical directional material")
	}
	if keysA.InitiatorToResponder == keysA.ResponderToInitiator {
		t.Fatal("TX and RX keys must differ")
	}

	aliceEph2, _ := GenerateKeyPair()
	bobEph2, _ := GenerateKeyPair()
	eph2, err := aliceEph2.SharedSecret(bobEph2.Public[:])
	if err != nil {
		t.Fatal(err)
	}
	keys2, err := DeriveSessionKeys(
		staticAB, eph2, 1002, 1, 2,
		aliceStatic.Public[:], bobStatic.Public[:],
		aliceEph2.Public[:], bobEph2.Public[:],
	)
	if err != nil {
		t.Fatal(err)
	}
	if keysA.InitiatorToResponder == keys2.InitiatorToResponder {
		t.Fatal("fresh handshake must derive a fresh traffic key")
	}
}

func TestHandshakeAuthenticationAndFinish(t *testing.T) {
	initiatorStatic, _ := GenerateKeyPair()
	responderStatic, _ := GenerateKeyPair()
	initiatorEph, _ := GenerateKeyPair()
	responderEph, _ := GenerateKeyPair()

	staticShared, err := initiatorStatic.SharedSecret(responderStatic.Public[:])
	if err != nil {
		t.Fatal(err)
	}
	sessionID := uint64(77)

	initTag, err := HandshakeInitAuthTag(
		staticShared, sessionID, 1, 2,
		initiatorStatic.Public[:], responderStatic.Public[:], initiatorEph.Public[:],
	)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyHandshakeInitAuth(
		staticShared, sessionID, 1, 2,
		initiatorStatic.Public[:], responderStatic.Public[:], initiatorEph.Public[:], initTag[:],
	) {
		t.Fatal("valid init auth rejected")
	}
	if VerifyHandshakeInitAuth(
		staticShared, sessionID+1, 1, 2,
		initiatorStatic.Public[:], responderStatic.Public[:], initiatorEph.Public[:], initTag[:],
	) {
		t.Fatal("init auth must bind session id")
	}

	respTag, err := HandshakeResponseAuthTag(
		staticShared, sessionID, 1, 2,
		initiatorStatic.Public[:], responderStatic.Public[:],
		initiatorEph.Public[:], responderEph.Public[:],
	)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyHandshakeResponseAuth(
		staticShared, sessionID, 1, 2,
		initiatorStatic.Public[:], responderStatic.Public[:],
		initiatorEph.Public[:], responderEph.Public[:], respTag[:],
	) {
		t.Fatal("valid response auth rejected")
	}

	ephShared, err := initiatorEph.SharedSecret(responderEph.Public[:])
	if err != nil {
		t.Fatal(err)
	}
	keys, err := DeriveSessionKeys(
		staticShared, ephShared, sessionID, 1, 2,
		initiatorStatic.Public[:], responderStatic.Public[:],
		initiatorEph.Public[:], responderEph.Public[:],
	)
	if err != nil {
		t.Fatal(err)
	}
	finish, err := FinishAuthTag(
		keys.Finish, sessionID, 1, 2,
		initiatorStatic.Public[:], responderStatic.Public[:],
		initiatorEph.Public[:], responderEph.Public[:],
	)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyFinishAuth(
		keys.Finish, sessionID, 1, 2,
		initiatorStatic.Public[:], responderStatic.Public[:],
		initiatorEph.Public[:], responderEph.Public[:], finish[:],
	) {
		t.Fatal("valid finish auth rejected")
	}

	wrong := keys.Finish
	wrong[0] ^= 0xff
	if VerifyFinishAuth(
		wrong, sessionID, 1, 2,
		initiatorStatic.Public[:], responderStatic.Public[:],
		initiatorEph.Public[:], responderEph.Public[:], finish[:],
	) {
		t.Fatal("finish accepted with wrong key")
	}
}
