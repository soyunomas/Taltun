package protocol

import (
	"encoding/binary"
	"errors"
)

// Constantes de tamaño y offsets
const (
	HeaderSize = 17 // 1 Type + 4 SessionID + 12 Nonce
	NonceSize  = 12
)

// Tipos de paquete
const (
	MsgTypeHandshakeInit  uint8 = 0x01 // Cliente -> Servidor (Hola, esta es mi PubKey)
	MsgTypeHandshakeResp  uint8 = 0x02 // Servidor -> Cliente (Hola, esta es la mia)
	MsgTypeData           uint8 = 0x03 // Tráfico VPN Cifrado
	MsgTypeCookieReply    uint8 = 0x04 // Servidor -> Cliente (Estás rate-limited, usa esta cookie)
	MsgTypePeerUpdate     uint8 = 0x05 // Faro -> Cliente (El peer X ha cambiado de IP/Puerto)
)

var (
	ErrBufferTooSmall = errors.New("buffer too small for header")
)

// EncodeDataHeader escribe la cabecera en el buffer dst.
func EncodeDataHeader(dst []byte, sessionID uint32, nonce []byte) (int, error) {
	if len(dst) < HeaderSize {
		return 0, ErrBufferTooSmall
	}
	if len(nonce) != NonceSize {
		return 0, errors.New("invalid nonce size")
	}

	dst[0] = MsgTypeData
	binary.BigEndian.PutUint32(dst[1:5], sessionID)
	copy(dst[5:17], nonce)

	return HeaderSize, nil
}

// ParseHeader lee la cabecera del buffer src sin alocar memoria.
func ParseHeader(src []byte) (msgType uint8, sessionID uint32, nonce []byte, payload []byte, err error) {
	if len(src) < HeaderSize {
		return 0, 0, nil, nil, ErrBufferTooSmall
	}

	msgType = src[0]
	// Para paquetes Data, leemos Session y Nonce.
	// Para Handshake y Control, el formato es distinto y se parsea en su módulo específico,
	// pero ParseHeader sirve para identificar el tipo (byte 0).
	
	sessionID = binary.BigEndian.Uint32(src[1:5])
	nonce = src[5:17]
	payload = src[17:]

	return msgType, sessionID, nonce, payload, nil
}
