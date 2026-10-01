package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

const (
	KeySize = 32
)

// KeyPair contiene las claves asimétricas X25519.
type KeyPair struct {
	Private [KeySize]byte
	Public  [KeySize]byte
}

// GenerateKeyPair crea un par de claves X25519 aleatorias.
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

// NewKeyPairFromPrivate carga una identidad estática desde una clave privada existente.
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

// SharedSecret calcula el secreto crudo X25519.
//
// X25519 devuelve error para entradas de bajo orden que producirían un secreto
// todo-cero. Es importante propagar ese error: aceptar esos puntos convertiría
// el secreto compartido en un valor conocido por un atacante.
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

// DeriveSessionKey convierte el secreto compartido ECDH en una clave AEAD usando KDF (Blake2s).
//
// Esta función se mantiene durante la transición al protocolo de sesión v2.
// El siguiente paso del plan sustituirá la clave única por claves TX/RX
// direccionales derivadas de un transcript autenticado y efímero.
func DeriveSessionKey(sharedSecret [KeySize]byte, context string) (cipher.AEAD, error) {
	kdf, err := blake2s.New256(nil)
	if err != nil {
		return nil, err
	}
	if _, err := kdf.Write(sharedSecret[:]); err != nil {
		return nil, err
	}
	if _, err := kdf.Write([]byte(context)); err != nil {
		return nil, err
	}

	key := kdf.Sum(nil)
	return chacha20poly1305.New(key)
}
