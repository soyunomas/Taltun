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
				if p.NeedsKeepalive() {
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
	
	// OPTIMIZACION (STACK)
	var nonceArr [protocol.NonceSize]byte
	nonceBuf := nonceArr[:]
	
	// Nonce Random Prefix + Counter
	copy(nonceBuf[0:4], []byte{0xCA, 0xFE, 0xBA, 0xBE})
	ctr := atomic.AddUint64(&e.txCounter, 1)
	binary.BigEndian.PutUint64(nonceBuf[4:], ctr)

	protocol.EncodeDataHeader(pkt[:], e.localVIP, nonceBuf)
	
	// Payload vacío para Keepalive
	encrypted := aead.Seal(pkt[protocol.HeaderSize:protocol.HeaderSize], nonceBuf, nil, nil)
	totalLen := protocol.HeaderSize + len(encrypted)

	p.UpdateTimestamps(false)

	// CAMBIO CRÍTICO: Enviar via Batch Channel en lugar de Syscall directa.
	// Esto permite que dataplane_tx agrupe este paquete con otros de datos.
	req := txRequest{
		Data: pkt[:totalLen],
		Buff: pkt, // Pasamos ownership del buffer al worker TX
		Addr: endpoint,
	}

	// Obtener un Batch nuevo o reusado (Single Packet Batch para control es aceptable)
	// Idealmente dataplane_tx agregaría, pero aquí forzamos inyección.
	newBatch := txBatchPool.Get().(*TxBatch)
	newBatch.Reqs[0] = req
	newBatch.Len = 1

	select {
	case e.txCh <- newBatch:
		// Enviado al worker TX
	default:
		// Si el canal está lleno (congestión), descartamos el Keepalive.
		// Es mejor perder un keepalive que bloquear el housekeeping o allocar memoria infinita.
		pool.Put(pkt)
		txBatchPool.Put(newBatch)
	}
}

// --- HANDSHAKE PROTOCOL (Sin cambios mayores, usa UDP directo por baja frecuencia) ---

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
	peer.SetEndpoint(req.RemoteAddr)
	
	log.Printf("🔐 Handshake Completado con %s (%s)", netutil.Uint32ToIP(senderVIP), req.RemoteAddr)

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
