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

// KeyPair contiene las claves asimétricas para ECDH.
type KeyPair struct {
	Private [KeySize]byte
	Public  [KeySize]byte
}

// GenerateKeyPair crea un par de claves efímeras aleatorias.
func GenerateKeyPair() (*KeyPair, error) {
	kp := &KeyPair{}
	if _, err := io.ReadFull(rand.Reader, kp.Private[:]); err != nil {
		return nil, fmt.Errorf("rng fail: %v", err)
	}
	curve25519.ScalarBaseMult(&kp.Public, &kp.Private)
	return kp, nil
}

// NewKeyPairFromPrivate carga una identidad estática desde una clave privada existente.
func NewKeyPairFromPrivate(priv []byte) (*KeyPair, error) {
	if len(priv) != KeySize {
		return nil, fmt.Errorf("invalid private key size: %d", len(priv))
	}
	kp := &KeyPair{}
	copy(kp.Private[:], priv)
	curve25519.ScalarBaseMult(&kp.Public, &kp.Private)
	return kp, nil
}

// SharedSecret calcula el secreto crudo ECDH.
func (kp *KeyPair) SharedSecret(peerPublic []byte) ([KeySize]byte, error) {
	var secret [KeySize]byte
	var pub [KeySize]byte

	if len(peerPublic) != KeySize {
		return secret, fmt.Errorf("invalid peer key size")
	}
	copy(pub[:], peerPublic)

	curve25519.ScalarMult(&secret, &kp.Private, &pub)
	return secret, nil
}

// DeriveSessionKey convierte el secreto compartido ECDH en una clave AEAD usando KDF (Blake2s).
// Esto es crucial: No usar el output de Curve25519 directamente como clave simétrica.
func DeriveSessionKey(sharedSecret [KeySize]byte, context string) (cipher.AEAD, error) {
	// KDF simple usando Blake2s
	kdf, err := blake2s.New256(nil)
	if err != nil {
		return nil, err
	}
	kdf.Write(sharedSecret[:])
	kdf.Write([]byte(context)) // Contexto para separar claves si fuera necesario (ej. Tx vs Rx)
	
	key := kdf.Sum(nil)

	return chacha20poly1305.New(key)
}
