package engine

import (
	"encoding/binary"
	"net"

	"github.com/Soyunomas/taltun/pkg/pool"
	"github.com/Soyunomas/taltun/pkg/protocol"
)

func (e *Engine) processPeerUpdatePacket(pkt []byte, rAddr *net.UDPAddr) {
	_, senderVIP, sessionID, nonce, ciphertext, err := protocol.ParseControlHeader(pkt)
	if err != nil {
		return
	}

	currentPeers := *e.peers.Load()
	lighthouse := currentPeers[senderVIP]
	if lighthouse == nil || !lighthouse.IsLighthouse() {
		return
	}

	counter := binary.BigEndian.Uint64(nonce[4:12])
	plaintext, err := lighthouse.Open(
		sessionID,
		nil,
		nonce,
		ciphertext,
		pkt[:protocol.HeaderSize],
		counter,
	)
	if err != nil {
		return
	}

	targetVIP, candidate, err := protocol.ParsePeerUpdatePayload(plaintext)
	if err != nil {
		return
	}
	target := currentPeers[targetVIP]
	if target == nil || target == lighthouse {
		return
	}

	// The update is only a discovery hint. Trust moves to the candidate endpoint
	// only after the target completes the authenticated ephemeral handshake.
	e.sendHandshakeInitToV2(target, candidate)

	// The lighthouse packet itself was authenticated by its current session, so
	// endpoint migration for the lighthouse may follow normal authenticated traffic.
	if rAddr != nil {
		lighthouse.SetEndpoint(cloneUDPAddr(rAddr))
	}
}

func (e *Engine) sendPeerUpdate(dest *PeerInfo, aboutVIP uint32, aboutAddr *net.UDPAddr) {
	if dest == nil || aboutAddr == nil {
		return
	}
	endpoint := dest.GetEndpoint()
	sessionID, aead, counter, ok := dest.NextOutbound()
	if endpoint == nil || !ok {
		return
	}

	bufPtr := pool.Get()
	buf := bufPtr[:]
	var nonce [protocol.NonceSize]byte
	binary.BigEndian.PutUint64(nonce[4:], counter)

	if _, err := protocol.EncodeControlHeader(
		buf[:protocol.HeaderSize],
		protocol.MsgTypePeerUpdate,
		e.localVIP,
		sessionID,
		nonce[:],
	); err != nil {
		pool.Put(bufPtr)
		return
	}

	payloadStart := protocol.HeaderSize
	payloadEnd := payloadStart + protocol.PeerUpdatePayloadSize
	if _, err := protocol.EncodePeerUpdatePayload(buf[payloadStart:payloadEnd], aboutVIP, aboutAddr); err != nil {
		pool.Put(bufPtr)
		return
	}

	encrypted := aead.Seal(
		buf[payloadStart:payloadStart],
		nonce[:],
		buf[payloadStart:payloadEnd],
		buf[:protocol.HeaderSize],
	)
	totalLen := protocol.HeaderSize + len(encrypted)

	req := txRequest{Data: buf[:totalLen], Buff: bufPtr, Addr: endpoint}
	batch := txBatchPool.Get().(*TxBatch)
	batch.Reqs[0] = req
	batch.Len = 1

	select {
	case e.txCh <- batch:
	case <-e.done:
		pool.Put(bufPtr)
		batch.Reqs[0] = txRequest{}
		batch.Len = 0
		txBatchPool.Put(batch)
	default:
		pool.Put(bufPtr)
		batch.Reqs[0] = txRequest{}
		batch.Len = 0
		txBatchPool.Put(batch)
	}
}

func cloneUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	ip := append(net.IP(nil), addr.IP...)
	return &net.UDPAddr{IP: ip, Port: addr.Port, Zone: addr.Zone}
}
