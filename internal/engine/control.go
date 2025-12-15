package engine

import (
	"context"
	"encoding/binary"
	"log"
	"net"
	"sync/atomic"
	"time"

	"github.com/Soyunomas/taltun/pkg/crypto"
	"github.com/Soyunomas/taltun/pkg/netutil"
	"github.com/Soyunomas/taltun/pkg/pool"
	"github.com/Soyunomas/taltun/pkg/protocol"
)

// --- HOUSEKEEPING (Rekey + Keepalives) ---

func (e *Engine) housekeepingWorker(ctx context.Context) error {
	// Aumentamos frecuencia para asegurar NAT traversal agresivo
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			currentPeers := *e.peers.Load()
			for _, p := range currentPeers {
				if p.NeedsRekey() {
					p.MarkHandshakePending()
					e.sendHandshakeInit(p)
				}
				// Keepalive agresivo si el peer tiene endpoint (crucial para Lighthouse)
				if p.GetEndpoint() != nil && p.NeedsKeepalive() {
					e.sendKeepalive(p)
				}
			}
		}
	}
}

func (e *Engine) sendKeepalive(p *PeerInfo) {
	aead := p.GetAEAD()
	endpoint := p.GetEndpoint()
	if aead == nil || endpoint == nil {
		return
	}

	pkt := pool.Get()
	
	var nonceArr [protocol.NonceSize]byte
	nonceBuf := nonceArr[:]
	
	copy(nonceBuf[0:4], []byte{0xCA, 0xFE, 0xBA, 0xBE})
	ctr := atomic.AddUint64(&e.txCounter, 1)
	binary.BigEndian.PutUint64(nonceBuf[4:], ctr)

	protocol.EncodeDataHeader(pkt[:], e.localVIP, nonceBuf)
	
	encrypted := aead.Seal(pkt[protocol.HeaderSize:protocol.HeaderSize], nonceBuf, nil, nil)
	totalLen := protocol.HeaderSize + len(encrypted)

	p.UpdateTimestamps(false)

	req := txRequest{
		Data: pkt[:totalLen],
		Buff: pkt, 
		Addr: endpoint,
	}

	newBatch := txBatchPool.Get().(*TxBatch)
	newBatch.Reqs[0] = req
	newBatch.Len = 1

	select {
	case e.txCh <- newBatch:
	default:
		pool.Put(pkt)
		txBatchPool.Put(newBatch)
	}
}

// --- HANDSHAKE PROTOCOL ---

func (e *Engine) handshakeWorker() {
	for req := range e.handshakeCh {
		e.processHandshake(req)
	}
}

func (e *Engine) processHandshake(req HandshakeRequest) {
	senderVIP, pubKey, _, err := protocol.ParseHandshake(req.Packet)
	if err != nil {
		return
	}

	currentPeers := *e.peers.Load()
	peer, exists := currentPeers[senderVIP]

	if !exists {
		return
	}

	sharedSecret, err := e.staticKey.SharedSecret(pubKey)
	if err != nil {
		return
	}

	sessionAEAD, err := crypto.DeriveSessionKey(sharedSecret, "taltun-session-v1")
	if err != nil {
		return
	}

	peer.SetSessionKey(sessionAEAD)
	
	// ACTUALIZACIÓN DE ENDPOINT & RUTA (Hole Punching Success)
	prevEndpoint := peer.GetEndpoint()
	newEndpoint := req.RemoteAddr
	
	// Si el endpoint ha cambiado (o es el primero que descubrimos), actualizamos
	updateRoute := false
	if prevEndpoint == nil {
		updateRoute = true
	} else if !prevEndpoint.IP.Equal(newEndpoint.IP) || prevEndpoint.Port != newEndpoint.Port {
		updateRoute = true
	}

	if updateRoute {
		peer.SetEndpoint(newEndpoint)
		// ¡IMPORTANTE! Promocionamos la ruta directa.
		// Esto activa el tráfico P2P directo y deja de usar el Relay del Faro.
		e.PromotePeerRoute(peer)
		
		if e.cfg.Debug {
			log.Printf("✨ Ruta Directa Establecida: %s -> %s (P2P)", 
				netutil.Uint32ToIP(senderVIP), newEndpoint)
		}
	} else {
		log.Printf("🔐 Handshake Renovado con %s", netutil.Uint32ToIP(senderVIP))
	}

	if req.Packet[0] == protocol.MsgTypeHandshakeInit {
		e.sendHandshakeResp(peer, req.RemoteAddr)
	}
}

func (e *Engine) sendHandshakeInit(p *PeerInfo) {
	cookie := p.GetCookie()
	e.sendHandshakePacket(e.localVIP, protocol.MsgTypeHandshakeInit, e.staticKey.Public[:], p.GetEndpoint(), cookie)
}

func (e *Engine) sendHandshakeResp(p *PeerInfo, addr *net.UDPAddr) {
	e.sendHandshakePacket(e.localVIP, protocol.MsgTypeHandshakeResp, e.staticKey.Public[:], addr, nil)
}

func (e *Engine) sendHandshakePacket(senderVIP uint32, msgType uint8, pubKey []byte, addr *net.UDPAddr, cookie []byte) {
	if addr == nil {
		return
	}
	pkt := pool.Get()
	defer pool.Put(pkt)

	n, _ := protocol.EncodeHandshake(pkt[:], msgType, senderVIP, pubKey, cookie)
	
	if len(e.rawConns) > 0 {
		e.rawConns[0].WriteToUDP(pkt[:n], addr)
	}
}

func (e *Engine) sendCookieReply(addr *net.UDPAddr, cookie []byte, sockIdx int) {
	pkt := pool.Get()
	defer pool.Put(pkt)

	n, _ := protocol.EncodeCookieReply(pkt[:], cookie)
	
	if sockIdx < len(e.rawConns) {
		e.rawConns[sockIdx].WriteToUDP(pkt[:n], addr)
	}
}
