package crypto

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const KeySize = 32

type KeyPair struct {
	Private [KeySize]byte
	Public  [KeySize]byte
}

type SessionKeys struct {
	InitiatorToResponder [KeySize]byte
	ResponderToInitiator [KeySize]byte
	Finish               [KeySize]byte
}

func GenerateKeyPair() (*KeyPair, error) {
	kp := &KeyPair{}
	if _, err := io.ReadFull(rand.Reader, kp.Private[:]); err != nil {
		return nil, fmt.Errorf("rng fail: %w", err)
	}

	public, err := curve25519.X25519(kp.Private[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("derive public key: %w", err)
	}
	copy(kp.Public[:], public)
	return kp, nil
}

func NewKeyPairFromPrivate(priv []byte) (*KeyPair, error) {
	if len(priv) != KeySize {
		return nil, fmt.Errorf("invalid private key size: %d", len(priv))
	}

	kp := &KeyPair{}
	copy(kp.Private[:], priv)

	public, err := curve25519.X25519(kp.Private[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("derive public key: %w", err)
	}
	copy(kp.Public[:], public)
	return kp, nil
}

func (kp *KeyPair) SharedSecret(peerPublic []byte) ([KeySize]byte, error) {
	var secret [KeySize]byte
	if len(peerPublic) != KeySize {
		return secret, fmt.Errorf("invalid peer key size: %d", len(peerPublic))
	}

	shared, err := curve25519.X25519(kp.Private[:], peerPublic)
	if err != nil {
		return secret, fmt.Errorf("invalid peer public key: %w", err)
	}
	copy(secret[:], shared)
	return secret, nil
}

func NewAEAD(key [KeySize]byte) (cipher.AEAD, error) {
	return chacha20poly1305.New(key[:])
}

func GenerateSessionID() (uint64, error) {
	var raw [8]byte
	for {
		if _, err := io.ReadFull(rand.Reader, raw[:]); err != nil {
			return 0, fmt.Errorf("session id rng fail: %w", err)
		}
		id := binary.BigEndian.Uint64(raw[:])
		if id != 0 {
			return id, nil
		}
	}
}

func HandshakeInitAuthTag(
	staticShared [KeySize]byte,
	sessionID uint64,
	initiatorVIP, responderVIP uint32,
	initiatorStatic, responderStatic, initiatorEphemeral []byte,
) ([sha256.Size]byte, error) {
	var tag [sha256.Size]byte
	if err := validatePublicKeys(initiatorStatic, responderStatic, initiatorEphemeral); err != nil {
		return tag, err
	}

	mac := hmac.New(sha256.New, staticShared[:])
	writeLabel(mac, "taltun-handshake-init-v2")
	writeSessionIdentity(mac, sessionID, initiatorVIP, responderVIP)
	_, _ = mac.Write(initiatorStatic)
	_, _ = mac.Write(responderStatic)
	_, _ = mac.Write(initiatorEphemeral)
	copy(tag[:], mac.Sum(nil))
	return tag, nil
}

func VerifyHandshakeInitAuth(
	staticShared [KeySize]byte,
	sessionID uint64,
	initiatorVIP, responderVIP uint32,
	initiatorStatic, responderStatic, initiatorEphemeral, receivedTag []byte,
) bool {
	if len(receivedTag) != sha256.Size {
		return false
	}
	expected, err := HandshakeInitAuthTag(
		staticShared,
		sessionID,
		initiatorVIP,
		responderVIP,
		initiatorStatic,
		responderStatic,
		initiatorEphemeral,
	)
	return err == nil && hmac.Equal(expected[:], receivedTag)
}

func HandshakeResponseAuthTag(
	staticShared [KeySize]byte,
	sessionID uint64,
	initiatorVIP, responderVIP uint32,
	initiatorStatic, responderStatic, initiatorEphemeral, responderEphemeral []byte,
) ([sha256.Size]byte, error) {
	var tag [sha256.Size]byte
	transcript, err := SessionTranscriptHash(
		sessionID,
		initiatorVIP,
		responderVIP,
		initiatorStatic,
		responderStatic,
		initiatorEphemeral,
		responderEphemeral,
	)
	if err != nil {
		return tag, err
	}

	mac := hmac.New(sha256.New, staticShared[:])
	writeLabel(mac, "taltun-handshake-response-v2")
	_, _ = mac.Write(transcript[:])
	copy(tag[:], mac.Sum(nil))
	return tag, nil
}

func VerifyHandshakeResponseAuth(
	staticShared [KeySize]byte,
	sessionID uint64,
	initiatorVIP, responderVIP uint32,
	initiatorStatic, responderStatic, initiatorEphemeral, responderEphemeral, receivedTag []byte,
) bool {
	if len(receivedTag) != sha256.Size {
		return false
	}
	expected, err := HandshakeResponseAuthTag(
		staticShared,
		sessionID,
		initiatorVIP,
		responderVIP,
		initiatorStatic,
		responderStatic,
		initiatorEphemeral,
		responderEphemeral,
	)
	return err == nil && hmac.Equal(expected[:], receivedTag)
}

func SessionTranscriptHash(
	sessionID uint64,
	initiatorVIP, responderVIP uint32,
	initiatorStatic, responderStatic, initiatorEphemeral, responderEphemeral []byte,
) ([sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	if err := validatePublicKeys(initiatorStatic, responderStatic, initiatorEphemeral, responderEphemeral); err != nil {
		return zero, err
	}

	h := sha256.New()
	writeLabel(h, "taltun-session-transcript-v2")
	writeSessionIdentity(h, sessionID, initiatorVIP, responderVIP)
	_, _ = h.Write(initiatorStatic)
	_, _ = h.Write(responderStatic)
	_, _ = h.Write(initiatorEphemeral)
	_, _ = h.Write(responderEphemeral)

	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

func DeriveSessionKeys(
	staticShared, ephemeralShared [KeySize]byte,
	sessionID uint64,
	initiatorVIP, responderVIP uint32,
	initiatorStatic, responderStatic, initiatorEphemeral, responderEphemeral []byte,
) (SessionKeys, error) {
	var keys SessionKeys
	transcript, err := SessionTranscriptHash(
		sessionID,
		initiatorVIP,
		responderVIP,
		initiatorStatic,
		responderStatic,
		initiatorEphemeral,
		responderEphemeral,
	)
	if err != nil {
		return keys, err
	}

	info := make([]byte, 0, len("taltun-session-keys-v2")+len(transcript))
	info = append(info, []byte("taltun-session-keys-v2")...)
	info = append(info, transcript[:]...)

	reader := hkdf.New(sha256.New, ephemeralShared[:], staticShared[:], info)
	material := make([]byte, KeySize*3)
	if _, err := io.ReadFull(reader, material); err != nil {
		return keys, fmt.Errorf("derive session keys: %w", err)
	}

	copy(keys.InitiatorToResponder[:], material[0:KeySize])
	copy(keys.ResponderToInitiator[:], material[KeySize:KeySize*2])
	copy(keys.Finish[:], material[KeySize*2:KeySize*3])
	return keys, nil
}

func FinishAuthTag(
	finishKey [KeySize]byte,
	sessionID uint64,
	initiatorVIP, responderVIP uint32,
	initiatorStatic, responderStatic, initiatorEphemeral, responderEphemeral []byte,
) ([sha256.Size]byte, error) {
	var tag [sha256.Size]byte
	transcript, err := SessionTranscriptHash(
		sessionID,
		initiatorVIP,
		responderVIP,
		initiatorStatic,
		responderStatic,
		initiatorEphemeral,
		responderEphemeral,
	)
	if err != nil {
		return tag, err
	}

	mac := hmac.New(sha256.New, finishKey[:])
	writeLabel(mac, "taltun-handshake-finish-v2")
	_, _ = mac.Write(transcript[:])
	copy(tag[:], mac.Sum(nil))
	return tag, nil
}

func VerifyFinishAuth(
	finishKey [KeySize]byte,
	sessionID uint64,
	initiatorVIP, responderVIP uint32,
	initiatorStatic, responderStatic, initiatorEphemeral, responderEphemeral, receivedTag []byte,
) bool {
	if len(receivedTag) != sha256.Size {
		return false
	}
	expected, err := FinishAuthTag(
		finishKey,
		sessionID,
		initiatorVIP,
		responderVIP,
		initiatorStatic,
		responderStatic,
		initiatorEphemeral,
		responderEphemeral,
	)
	return err == nil && hmac.Equal(expected[:], receivedTag)
}

func validatePublicKeys(keys ...[]byte) error {
	for _, key := range keys {
		if len(key) != KeySize {
			return fmt.Errorf("invalid public key size: %d", len(key))
		}
	}
	return nil
}

func writeLabel(w io.Writer, label string) {
	_, _ = io.WriteString(w, label)
}

func writeSessionIdentity(w io.Writer, sessionID uint64, initiatorVIP, responderVIP uint32) {
	var buf [16]byte
	binary.BigEndian.PutUint64(buf[0:8], sessionID)
	binary.BigEndian.PutUint32(buf[8:12], initiatorVIP)
	binary.BigEndian.PutUint32(buf[12:16], responderVIP)
	_, _ = w.Write(buf[:])
}
