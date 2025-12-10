package protocol

import (
	"encoding/binary"
	"errors"
)

const (
	HandshakeSize = 37 // 1 Type + 4 SenderIndex + 32 PubKey
)

// EncodeHandshake serializa un mensaje de inicio de conexión.
// type: Init o Resp
// localIndex: El ID de sesión que el remitente quiere usar (para recibir).
// pubKey: La clave pública efímera (32 bytes).
func EncodeHandshake(dst []byte, msgType uint8, localIndex uint32, pubKey []byte) (int, error) {
	if len(dst) < HandshakeSize {
		return 0, errors.New("buffer too small")
	}
	if len(pubKey) != 32 {
		return 0, errors.New("invalid pubkey size")
	}

	dst[0] = msgType
	binary.BigEndian.PutUint32(dst[1:5], localIndex)
	copy(dst[5:37], pubKey)

	return HandshakeSize, nil
}

// ParseHandshake decodifica el mensaje.
func ParseHandshake(src []byte) (senderIndex uint32, pubKey []byte, err error) {
	if len(src) < HandshakeSize {
		return 0, nil, errors.New("packet too small for handshake")
	}
	
	// Byte 0 es Type (ya leído fuera)
	senderIndex = binary.BigEndian.Uint32(src[1:5])
	pubKey = src[5:37] // Zero-copy view
	
	return senderIndex, pubKey, nil
}
