package protocol

import (
	"encoding/binary"
	"errors"
)

const (
	HeaderSize = 25 // 1 Type + 4 SenderVIP + 8 SessionID + 12 Nonce
	NonceSize  = 12
)

const (
	MsgTypeHandshakeInit   uint8 = 0x01
	MsgTypeHandshakeResp   uint8 = 0x02
	MsgTypeData            uint8 = 0x03
	MsgTypeCookieReply     uint8 = 0x04
	MsgTypeHandshakeFinish uint8 = 0x05
)

var ErrBufferTooSmall = errors.New("buffer too small for header")

func EncodeDataHeader(dst []byte, senderVIP uint32, sessionID uint64, nonce []byte) (int, error) {
	if len(dst) < HeaderSize {
		return 0, ErrBufferTooSmall
	}
	if sessionID == 0 {
		return 0, errors.New("invalid zero session id")
	}
	if len(nonce) != NonceSize {
		return 0, errors.New("invalid nonce size")
	}

	dst[0] = MsgTypeData
	binary.BigEndian.PutUint32(dst[1:5], senderVIP)
	binary.BigEndian.PutUint64(dst[5:13], sessionID)
	copy(dst[13:25], nonce)
	return HeaderSize, nil
}

func ParseHeader(src []byte) (msgType uint8, senderVIP uint32, sessionID uint64, nonce, payload []byte, err error) {
	if len(src) < HeaderSize {
		return 0, 0, 0, nil, nil, ErrBufferTooSmall
	}

	msgType = src[0]
	if msgType != MsgTypeData {
		return 0, 0, 0, nil, nil, errors.New("invalid data message type")
	}
	senderVIP = binary.BigEndian.Uint32(src[1:5])
	sessionID = binary.BigEndian.Uint64(src[5:13])
	if sessionID == 0 {
		return 0, 0, 0, nil, nil, errors.New("invalid zero session id")
	}
	nonce = src[13:25]
	payload = src[25:]
	return msgType, senderVIP, sessionID, nonce, payload, nil
}
