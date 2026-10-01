package protocol

import (
	"encoding/binary"
	"errors"
	"net"
)

const (
	MsgTypePeerUpdate uint8 = 0x06
	PeerUpdatePayloadSize   = 10 // target VIP + IPv4 + port
)

func EncodeControlHeader(dst []byte, msgType uint8, senderVIP uint32, sessionID uint64, nonce []byte) (int, error) {
	if msgType != MsgTypePeerUpdate {
		return 0, errors.New("unsupported control message type")
	}
	if len(dst) < HeaderSize {
		return 0, ErrBufferTooSmall
	}
	if sessionID == 0 {
		return 0, errors.New("invalid zero session id")
	}
	if len(nonce) != NonceSize {
		return 0, errors.New("invalid nonce size")
	}

	dst[0] = msgType
	binary.BigEndian.PutUint32(dst[1:5], senderVIP)
	binary.BigEndian.PutUint64(dst[5:13], sessionID)
	copy(dst[13:25], nonce)
	return HeaderSize, nil
}

func ParseControlHeader(src []byte) (msgType uint8, senderVIP uint32, sessionID uint64, nonce, payload []byte, err error) {
	if len(src) < HeaderSize {
		return 0, 0, 0, nil, nil, ErrBufferTooSmall
	}
	if src[0] != MsgTypePeerUpdate {
		return 0, 0, 0, nil, nil, errors.New("unsupported control message type")
	}

	msgType = src[0]
	senderVIP = binary.BigEndian.Uint32(src[1:5])
	sessionID = binary.BigEndian.Uint64(src[5:13])
	if sessionID == 0 {
		return 0, 0, 0, nil, nil, errors.New("invalid zero session id")
	}
	nonce = src[13:25]
	payload = src[25:]
	return msgType, senderVIP, sessionID, nonce, payload, nil
}

func EncodePeerUpdatePayload(dst []byte, targetVIP uint32, endpoint *net.UDPAddr) (int, error) {
	if len(dst) < PeerUpdatePayloadSize {
		return 0, errors.New("buffer too small for peer update")
	}
	if endpoint == nil {
		return 0, errors.New("nil endpoint")
	}
	ip4 := endpoint.IP.To4()
	if ip4 == nil {
		return 0, errors.New("ipv6 peer update not supported")
	}
	if endpoint.Port <= 0 || endpoint.Port > 65535 {
		return 0, errors.New("invalid endpoint port")
	}

	binary.BigEndian.PutUint32(dst[0:4], targetVIP)
	copy(dst[4:8], ip4)
	binary.BigEndian.PutUint16(dst[8:10], uint16(endpoint.Port))
	return PeerUpdatePayloadSize, nil
}

func ParsePeerUpdatePayload(src []byte) (targetVIP uint32, endpoint *net.UDPAddr, err error) {
	if len(src) != PeerUpdatePayloadSize {
		return 0, nil, errors.New("invalid peer update payload size")
	}

	targetVIP = binary.BigEndian.Uint32(src[0:4])
	if targetVIP == 0 {
		return 0, nil, errors.New("invalid target VIP")
	}
	ip := net.IPv4(src[4], src[5], src[6], src[7]).To4()
	port := int(binary.BigEndian.Uint16(src[8:10]))
	if port == 0 {
		return 0, nil, errors.New("invalid endpoint port")
	}
	return targetVIP, &net.UDPAddr{IP: ip, Port: port}, nil
}
