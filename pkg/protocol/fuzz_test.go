package protocol

import "testing"

func FuzzParseDataHeader(f *testing.F) {
	seed := make([]byte, HeaderSize)
	seed[0] = MsgTypeData
	seed[12] = 1
	f.Add(seed)
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _, _, _, _ = ParseHeader(data)
	})
}

func FuzzParseHandshake(f *testing.F) {
	seed := make([]byte, HandshakeInitSize)
	seed[0] = MsgTypeHandshakeInit
	seed[12] = 1
	f.Add(seed)
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseHandshake(data)
		if len(data) >= HandshakeFinishSize {
			_, _, _, _ = ParseHandshakeFinish(data)
		}
	})
}

func FuzzParseControl(f *testing.F) {
	seed := make([]byte, HeaderSize+PeerUpdatePayloadSize)
	seed[0] = MsgTypePeerUpdate
	seed[12] = 1
	f.Add(seed)
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _, _, payload, _ := ParseControlHeader(data)
		if payload != nil {
			_, _, _ = ParsePeerUpdatePayload(payload)
		}
		_, _ = ParseCookieReply(data)
	})
}
