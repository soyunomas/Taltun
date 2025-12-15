package protocol

import (
	"encoding/binary"
	"errors"
	"net"
)

const (
	HandshakeBaseSize = 37 // 1 Type + 4 SenderIndex + 32 PubKey
	CookieSize        = 16 // HMAC-MD5 o Blake2s truncado (suficiente para DoS protection)
	
	// Estructura PeerUpdate: [1 Type] + [4 TargetVIP] + [4 IP] + [2 Port]
	PeerUpdateSize    = 11 
)

// EncodeHandshake serializa un mensaje de inicio de conexión.
// Soporta un campo opcional 'cookie' para protección DoS.
func EncodeHandshake(dst []byte, msgType uint8, localIndex uint32, pubKey []byte, cookie []byte) (int, error) {
	requiredSize := HandshakeBaseSize + len(cookie)
	if len(dst) < requiredSize {
		return 0, errors.New("buffer too small")
	}
	if len(pubKey) != 32 {
		return 0, errors.New("invalid pubkey size")
	}

	dst[0] = msgType
	binary.BigEndian.PutUint32(dst[1:5], localIndex)
	copy(dst[5:37], pubKey)

	// Si hay cookie, la adjuntamos al final
	if len(cookie) > 0 {
		copy(dst[37:], cookie)
	}

	return requiredSize, nil
}

// ParseHandshake decodifica el mensaje.
// Retorna la cookie si está presente en el paquete.
func ParseHandshake(src []byte) (senderIndex uint32, pubKey []byte, cookie []byte, err error) {
	if len(src) < HandshakeBaseSize {
		return 0, nil, nil, errors.New("packet too small for handshake")
	}
	
	senderIndex = binary.BigEndian.Uint32(src[1:5])
	pubKey = src[5:37] // Zero-copy view
	
	if len(src) >= HandshakeBaseSize+CookieSize {
		cookie = src[37 : 37+CookieSize]
	}
	
	return senderIndex, pubKey, cookie, nil
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

// --- LIGHTHOUSE PROTOCOL EXTENSIONS ---

// EncodePeerUpdate construye un mensaje notificando la nueva ubicación de un peer.
// Se usa cuando el Faro detecta que un cliente ha cambiado de IP/Puerto.
func EncodePeerUpdate(dst []byte, targetVIP uint32, endpoint *net.UDPAddr) (int, error) {
	if len(dst) < PeerUpdateSize {
		return 0, errors.New("buffer too small for peer update")
	}
	
	ip4 := endpoint.IP.To4()
	if ip4 == nil {
		return 0, errors.New("ipv6 peer update not supported yet")
	}

	dst[0] = MsgTypePeerUpdate
	binary.BigEndian.PutUint32(dst[1:5], targetVIP)
	copy(dst[5:9], ip4)
	binary.BigEndian.PutUint16(dst[9:11], uint16(endpoint.Port))

	return PeerUpdateSize, nil
}

// ParsePeerUpdate extrae la información de ubicación del peer.
func ParsePeerUpdate(src []byte) (targetVIP uint32, endpoint *net.UDPAddr, err error) {
	if len(src) < PeerUpdateSize {
		return 0, nil, errors.New("packet too small for peer update")
	}

	targetVIP = binary.BigEndian.Uint32(src[1:5])
	
	ip := make(net.IP, 4)
	copy(ip, src[5:9])
	
	port := binary.BigEndian.Uint16(src[9:11])

	endpoint = &net.UDPAddr{
		IP:   ip,
		Port: int(port),
	}

	return targetVIP, endpoint, nil
}
