package engine

import (
	"log"
	"net"

	"github.com/Soyunomas/taltun/pkg/crypto"
	"github.com/Soyunomas/taltun/pkg/netutil"
	"github.com/Soyunomas/taltun/pkg/pool"
	"github.com/Soyunomas/taltun/pkg/protocol"
)

func (e *Engine) processHandshakeV2(req HandshakeRequest) {
	if len(req.Packet) == 0 {
		return
	}

	switch req.Packet[0] {
	case protocol.MsgTypeHandshakeInit, protocol.MsgTypeHandshakeResp:
		h, err := protocol.ParseHandshake(req.Packet)
		if err != nil {
			return
		}

		currentPeers := *e.peers.Load()
		peer := currentPeers[h.SenderVIP]
		if peer == nil || !peer.MatchesPublicKey(h.StaticPublic) {
			return
		}

		staticShared, err := e.staticKey.SharedSecret(h.StaticPublic)
		if err != nil {
			return
		}

		if h.Type == protocol.MsgTypeHandshakeInit {
			e.processHandshakeInitV2(peer, h, staticShared, req.RemoteAddr)
			return
		}
		e.processHandshakeResponseV2(peer, h, staticShared, req.RemoteAddr)

	case protocol.MsgTypeHandshakeFinish:
		e.processHandshakeFinishV2(req)
	}
}

func (e *Engine) processHandshakeInitV2(
	peer *PeerInfo,
	h protocol.Handshake,
	staticShared [crypto.KeySize]byte,
	addr *net.UDPAddr,
) {
	if peer.SessionIDInUse(h.SessionID) {
		return
	}
	if !crypto.VerifyHandshakeInitAuth(
		staticShared,
		h.SessionID,
		h.SenderVIP,
		e.localVIP,
		h.StaticPublic,
		e.staticKey.Public[:],
		h.Ephemeral,
		h.AuthTag,
	) {
		return
	}

	responderEphemeral, err := crypto.GenerateKeyPair()
	if err != nil {
		return
	}
	ephemeralShared, err := responderEphemeral.SharedSecret(h.Ephemeral)
	if err != nil {
		return
	}

	keys, err := crypto.DeriveSessionKeys(
		staticShared,
		ephemeralShared,
		h.SessionID,
		h.SenderVIP,
		e.localVIP,
		h.StaticPublic,
		e.staticKey.Public[:],
		h.Ephemeral,
		responderEphemeral.Public[:],
	)
	if err != nil {
		return
	}

	var initiatorEphemeral [crypto.KeySize]byte
	copy(initiatorEphemeral[:], h.Ephemeral)
	peer.SetResponderHandshake(h.SessionID, initiatorEphemeral, responderEphemeral, keys)

	authTag, err := crypto.HandshakeResponseAuthTag(
		staticShared,
		h.SessionID,
		h.SenderVIP,
		e.localVIP,
		h.StaticPublic,
		e.staticKey.Public[:],
		h.Ephemeral,
		responderEphemeral.Public[:],
	)
	if err != nil {
		peer.AbortHandshake(h.SessionID)
		return
	}

	e.sendHandshakePacketV2(
		protocol.MsgTypeHandshakeResp,
		h.SessionID,
		responderEphemeral.Public[:],
		authTag[:],
		addr,
		nil,
	)
}

func (e *Engine) processHandshakeResponseV2(
	peer *PeerInfo,
	h protocol.Handshake,
	staticShared [crypto.KeySize]byte,
	addr *net.UDPAddr,
) {
	initiatorEphemeral, ok := peer.GetInitiatorHandshake(h.SessionID)
	if !ok {
		return
	}

	if !crypto.VerifyHandshakeResponseAuth(
		staticShared,
		h.SessionID,
		e.localVIP,
		h.SenderVIP,
		e.staticKey.Public[:],
		h.StaticPublic,
		initiatorEphemeral.Public[:],
		h.Ephemeral,
		h.AuthTag,
	) {
		return
	}

	ephemeralShared, err := initiatorEphemeral.SharedSecret(h.Ephemeral)
	if err != nil {
		return
	}
	keys, err := crypto.DeriveSessionKeys(
		staticShared,
		ephemeralShared,
		h.SessionID,
		e.localVIP,
		h.SenderVIP,
		e.staticKey.Public[:],
		h.StaticPublic,
		initiatorEphemeral.Public[:],
		h.Ephemeral,
	)
	if err != nil {
		return
	}

	finishTag, err := crypto.FinishAuthTag(
		keys.Finish,
		h.SessionID,
		e.localVIP,
		h.SenderVIP,
		e.staticKey.Public[:],
		h.StaticPublic,
		initiatorEphemeral.Public[:],
		h.Ephemeral,
	)
	if err != nil {
		return
	}

	if err := peer.CompleteInitiatorHandshake(
		h.SessionID,
		keys.InitiatorToResponder,
		keys.ResponderToInitiator,
	); err != nil {
		return
	}
	peer.SetEndpoint(addr)
	e.sendHandshakeFinishV2(h.SessionID, finishTag[:], addr)

	log.Printf("🔐 Sesión v2 iniciada con %s id=%016x", netutil.Uint32ToIP(h.SenderVIP), h.SessionID)
}

func (e *Engine) processHandshakeFinishV2(req HandshakeRequest) {
	senderVIP, sessionID, authTag, err := protocol.ParseHandshakeFinish(req.Packet)
	if err != nil {
		return
	}

	currentPeers := *e.peers.Load()
	peer := currentPeers[senderVIP]
	if peer == nil {
		return
	}

	initiatorEphemeral, responderEphemeral, keys, ok := peer.GetResponderHandshake(sessionID)
	if !ok || responderEphemeral == nil {
		return
	}

	if !crypto.VerifyFinishAuth(
		keys.Finish,
		sessionID,
		senderVIP,
		e.localVIP,
		peer.PublicKey[:],
		e.staticKey.Public[:],
		initiatorEphemeral[:],
		responderEphemeral.Public[:],
		authTag,
	) {
		return
	}

	if err := peer.CompleteResponderHandshake(sessionID); err != nil {
		return
	}
	peer.SetEndpoint(req.RemoteAddr)

	log.Printf("🔐 Sesión v2 aceptada con %s id=%016x", netutil.Uint32ToIP(senderVIP), sessionID)
}

func (e *Engine) sendHandshakeInitV2(p *PeerInfo) {
	e.sendHandshakeInitToV2(p, p.GetEndpoint())
}

func (e *Engine) sendHandshakeInitToV2(p *PeerInfo, addr *net.UDPAddr) {
	if addr == nil {
		return
	}

	var sessionID uint64
	for {
		candidate, err := crypto.GenerateSessionID()
		if err != nil {
			return
		}
		if !p.SessionIDInUse(candidate) {
			sessionID = candidate
			break
		}
	}

	ephemeral, err := crypto.GenerateKeyPair()
	if err != nil {
		return
	}
	staticShared, err := e.staticKey.SharedSecret(p.PublicKey[:])
	if err != nil {
		return
	}
	authTag, err := crypto.HandshakeInitAuthTag(
		staticShared,
		sessionID,
		e.localVIP,
		p.VirtualIP,
		e.staticKey.Public[:],
		p.PublicKey[:],
		ephemeral.Public[:],
	)
	if err != nil {
		return
	}

	p.BeginInitiatorHandshake(sessionID, ephemeral)
	e.sendHandshakePacketV2(
		protocol.MsgTypeHandshakeInit,
		sessionID,
		ephemeral.Public[:],
		authTag[:],
		addr,
		p.GetCookie(),
	)
}

func (e *Engine) sendHandshakeFinishV2(sessionID uint64, authTag []byte, addr *net.UDPAddr) {
	if addr == nil {
		return
	}

	pkt := pool.Get()
	defer pool.Put(pkt)

	n, err := protocol.EncodeHandshakeFinish(pkt[:], e.localVIP, sessionID, authTag)
	if err != nil {
		return
	}
	if len(e.rawConns) > 0 {
		_, _ = e.rawConns[0].WriteToUDP(pkt[:n], addr)
	}
}

func (e *Engine) sendHandshakePacketV2(
	msgType uint8,
	sessionID uint64,
	ephemeralPublic, authTag []byte,
	addr *net.UDPAddr,
	cookie []byte,
) {
	if addr == nil {
		return
	}

	pkt := pool.Get()
	defer pool.Put(pkt)

	n, err := protocol.EncodeHandshake(
		pkt[:],
		msgType,
		e.localVIP,
		sessionID,
		e.staticKey.Public[:],
		ephemeralPublic,
		authTag,
		cookie,
	)
	if err != nil {
		return
	}

	if len(e.rawConns) > 0 {
		_, _ = e.rawConns[0].WriteToUDP(pkt[:n], addr)
	}
}
