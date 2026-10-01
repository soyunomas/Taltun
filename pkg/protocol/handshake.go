package protocol

import (
	"encoding/binary"
	"errors"
)

const (
	HandshakeInitSize     = 109 // type + senderVIP + sessionID + staticPub + ephemeralPub + authTag
	HandshakeResponseSize = 109 // same layout as init
	HandshakeFinishSize   = 45  // type + senderVIP + sessionID + finishTag
	AuthTagSize           = 32
	CookieSize            = 16
)

type Handshake struct {
	Type         uint8
	SenderVIP    uint32
	SessionID    uint64
	StaticPublic []byte
	Ephemeral    []byte
	AuthTag      []byte
	Cookie       []byte
}

func EncodeHandshake(
	dst []byte,
	msgType uint8,
	senderVIP uint32,
	sessionID uint64,
	staticPublic, ephemeralPublic, authTag, cookie []byte,
) (int, error) {
	if msgType != MsgTypeHandshakeInit && msgType != MsgTypeHandshakeResp {
		return 0, errors.New("invalid handshake message type")
	}
	if len(staticPublic) != 32 || len(ephemeralPublic) != 32 {
		return 0, errors.New("invalid handshake public key size")
	}
	if len(authTag) != AuthTagSize {
		return 0, errors.New("invalid auth tag size")
	}
	if len(cookie) != 0 && len(cookie) != CookieSize {
		return 0, errors.New("invalid cookie size")
	}

	required := HandshakeInitSize + len(cookie)
	if len(dst) < required {
		return 0, errors.New("buffer too small")
	}

	dst[0] = msgType
	binary.BigEndian.PutUint32(dst[1:5], senderVIP)
	binary.BigEndian.PutUint64(dst[5:13], sessionID)
	copy(dst[13:45], staticPublic)
	copy(dst[45:77], ephemeralPublic)
	copy(dst[77:109], authTag)
	if len(cookie) > 0 {
		copy(dst[109:125], cookie)
	}
	return required, nil
}

func ParseHandshake(src []byte) (Handshake, error) {
	var h Handshake
	if len(src) < HandshakeInitSize {
		return h, errors.New("packet too small for handshake")
	}

	h.Type = src[0]
	if h.Type != MsgTypeHandshakeInit && h.Type != MsgTypeHandshakeResp {
		return h, errors.New("invalid handshake message type")
	}
	h.SenderVIP = binary.BigEndian.Uint32(src[1:5])
	h.SessionID = binary.BigEndian.Uint64(src[5:13])
	if h.SessionID == 0 {
		return h, errors.New("invalid zero session id")
	}
	h.StaticPublic = src[13:45]
	h.Ephemeral = src[45:77]
	h.AuthTag = src[77:109]

	if len(src) == HandshakeInitSize+CookieSize {
		h.Cookie = src[109:125]
	} else if len(src) != HandshakeInitSize {
		return h, errors.New("invalid handshake packet size")
	}
	return h, nil
}

func EncodeHandshakeFinish(dst []byte, senderVIP uint32, sessionID uint64, authTag []byte) (int, error) {
	if len(authTag) != AuthTagSize {
		return 0, errors.New("invalid finish auth tag size")
	}
	if sessionID == 0 {
		return 0, errors.New("invalid zero session id")
	}
	if len(dst) < HandshakeFinishSize {
		return 0, errors.New("buffer too small")
	}

	dst[0] = MsgTypeHandshakeFinish
	binary.BigEndian.PutUint32(dst[1:5], senderVIP)
	binary.BigEndian.PutUint64(dst[5:13], sessionID)
	copy(dst[13:45], authTag)
	return HandshakeFinishSize, nil
}

func ParseHandshakeFinish(src []byte) (senderVIP uint32, sessionID uint64, authTag []byte, err error) {
	if len(src) != HandshakeFinishSize {
		return 0, 0, nil, errors.New("invalid handshake finish size")
	}
	if src[0] != MsgTypeHandshakeFinish {
		return 0, 0, nil, errors.New("invalid handshake finish type")
	}
	senderVIP = binary.BigEndian.Uint32(src[1:5])
	sessionID = binary.BigEndian.Uint64(src[5:13])
	if sessionID == 0 {
		return 0, 0, nil, errors.New("invalid zero session id")
	}
	authTag = src[13:45]
	return senderVIP, sessionID, authTag, nil
}

func EncodeCookieReply(dst []byte, cookie []byte) (int, error) {
	if len(cookie) != CookieSize {
		return 0, errors.New("invalid cookie size")
	}
	if len(dst) < 1+CookieSize {
		return 0, errors.New("buffer too small for cookie reply")
	}
	dst[0] = MsgTypeCookieReply
	copy(dst[1:], cookie)
	return 1 + CookieSize, nil
}

func ParseCookieReply(src []byte) ([]byte, error) {
	if len(src) != 1+CookieSize {
		return nil, errors.New("invalid cookie reply size")
	}
	if src[0] != MsgTypeCookieReply {
		return nil, errors.New("invalid cookie reply type")
	}
	return src[1:], nil
}
