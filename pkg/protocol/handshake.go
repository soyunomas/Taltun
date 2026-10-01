package protocol

import (
	"encoding/binary"
	"errors"
)

const (
	HandshakeBaseSize = 69 // 1 Type + 4 SenderIndex + 32 PubKey + 32 AuthTag
	AuthTagSize       = 32
	CookieSize        = 16 // HMAC-MD5 o Blake2s truncado (suficiente para DoS protection)
)

// EncodeHandshake serializa un mensaje de inicio de conexión.
// Soporta un campo opcional 'cookie' para protección DoS.
func EncodeHandshake(dst []byte, msgType uint8, localIndex uint32, pubKey, authTag, cookie []byte) (int, error) {
	requiredSize := HandshakeBaseSize + len(cookie)
	if len(dst) < requiredSize {
		return 0, errors.New("buffer too small")
	}
	if len(pubKey) != 32 {
		return 0, errors.New("invalid pubkey size")
	}
	if len(authTag) != AuthTagSize {
		return 0, errors.New("invalid auth tag size")
	}

	dst[0] = msgType
	binary.BigEndian.PutUint32(dst[1:5], localIndex)
	copy(dst[5:37], pubKey)
	copy(dst[37:69], authTag)

	if len(cookie) > 0 {
		copy(dst[69:], cookie)
	}

	return requiredSize, nil
}

// ParseHandshake decodifica el mensaje.
// Retorna la cookie si está presente en el paquete.
func ParseHandshake(src []byte) (senderIndex uint32, pubKey, authTag, cookie []byte, err error) {
	if len(src) < HandshakeBaseSize {
		return 0, nil, nil, nil, errors.New("packet too small for handshake")
	}
	
	senderIndex = binary.BigEndian.Uint32(src[1:5])
	pubKey = src[5:37] // Zero-copy view
	authTag = src[37:69]

	if len(src) >= HandshakeBaseSize+CookieSize {
		cookie = src[69 : 69+CookieSize]
	}

	return senderIndex, pubKey, authTag, cookie, nil
}

// EncodeCookieReply crea el paquete de respuesta de cookie.
// Estructura: Type (1) + Cookie (16)
func EncodeCookieReply(dst []byte, cookie []byte) (int, error) {
	if len(dst) < 1+len(cookie) {
		return 0, errors.New("buffer too small for cookie reply")
	}
	dst[0] = MsgTypeCookieReply
	copy(dst[1:], cookie)
	return 1 + len(cookie), nil
}

// ParseCookieReply extrae la cookie de un paquete de respuesta.
func ParseCookieReply(src []byte) ([]byte, error) {
	if len(src) < 1+CookieSize {
		return nil, errors.New("packet too small for cookie reply")
	}
	return src[1 : 1+CookieSize], nil
}
