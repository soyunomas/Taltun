package engine

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
	"sync/atomic"

	"github.com/Soyunomas/taltun/pkg/netutil"
	"github.com/Soyunomas/taltun/pkg/pool"
	"github.com/Soyunomas/taltun/pkg/protocol"
	
	"golang.org/x/net/ipv4"
)

func (e *Engine) loopUdpBatchToTun(conn *ipv4.PacketConn, sockIdx int) error {
	log.Printf("⚡ Batch RX Worker #%d iniciado", sockIdx)
	
	msgs := make([]ipv4.Message, BatchSize)
	buffers := make([]*pool.Buff, BatchSize)
	
	for i := range msgs {
		buffers[i] = pool.Get()
		msgs[i].Buffers = [][]byte{buffers[i][:]}
	}

	var lastVIP uint32
	var lastPeer *PeerInfo

	for {
		nMsgs, err := conn.ReadBatch(msgs, 0)
		if err != nil {
			if e.closed.Load() || strings.Contains(err.Error(), "closed network connection") {
				return nil
			}
			return fmt.Errorf("readbatch error: %v", err)
		}

		for i := 0; i < nMsgs; i++ {
			msg := msgs[i]
			n := msg.N
			rAddr := msg.Addr.(*net.UDPAddr)
			packet := buffers[i][:n]

			e.processOnePacket(packet, buffers[i], rAddr, sockIdx, &lastVIP, &lastPeer)
			
			buffers[i] = pool.Get()
			msgs[i].Buffers[0] = buffers[i][:]
		}
	}
}

func (e *Engine) processOnePacket(pkt []byte, originalBuff *pool.Buff, rAddr *net.UDPAddr, sockIdx int, lastVIP *uint32, lastPeer **PeerInfo) {
	if len(pkt) < 1 {
		pool.Put(originalBuff) 
		return
	}
	msgType := pkt[0]

	// 1. Control Plane
	if msgType == protocol.MsgTypeHandshakeInit || msgType == protocol.MsgTypeHandshakeResp {
		underLoad := len(e.handshakeCh) > 250
		
		_, _, cookie, err := protocol.ParseHandshake(pkt)
		if err != nil {
			pool.Put(originalBuff)
			return
		}

		if underLoad {
			validCookie := false
			if len(cookie) > 0 {
				if e.cookieProtector.ValidateCookie(rAddr.IP, cookie) {
					validCookie = true
				}
			}

			if !validCookie {
				replyCookie := e.cookieProtector.GenerateCookie(rAddr.IP)
				e.sendCookieReply(rAddr, replyCookie, sockIdx)
				pool.Put(originalBuff)
				return 
			}
		}

		handshakePkt := make([]byte, len(pkt))
		copy(handshakePkt, pkt)
		pool.Put(originalBuff)
		
		select {
		case e.handshakeCh <- HandshakeRequest{
			RemoteAddr: rAddr, 
			Packet: handshakePkt,
			ConnIndex: sockIdx,
		}:
		default:
		}
		return

	} else if msgType == protocol.MsgTypeCookieReply {
		cookieBytes, err := protocol.ParseCookieReply(pkt)
		if err == nil {
			currentPeers := *e.peers.Load()
			for _, p := range currentPeers {
				ep := p.GetEndpoint()
				if ep != nil && ep.IP.Equal(rAddr.IP) && ep.Port == rAddr.Port {
					p.SetCookie(cookieBytes)
					go e.sendHandshakeInit(p)
					break
				}
			}
		}
		pool.Put(originalBuff)
		return
	}

	// 2. Data Plane (Hot Path)
	_, senderVIP, nonce, ciphertext, err := protocol.ParseHeader(pkt)
	if err != nil {
		pool.Put(originalBuff)
		return
	}

	var peer *PeerInfo
	
	if *lastPeer != nil && *lastVIP == senderVIP {
		peer = *lastPeer
	} else {
		currentPeers := *e.peers.Load()
		peer = currentPeers[senderVIP]
		
		if peer != nil {
			*lastVIP = senderVIP
			*lastPeer = peer
		}
	}

	if peer == nil {
		pool.Put(originalBuff)
		return
	}

	plaintextBufPtr := pool.Get()
	
	// Abrir cifrado dejando Headroom para TUN (offset 16)
	plaintext, err := peer.Open(plaintextBufPtr[TunHeadroom:TunHeadroom], nonce, ciphertext, nil)
	if err != nil {
		pool.Put(plaintextBufPtr)
		pool.Put(originalBuff)
		return
	}
	
	pool.Put(originalBuff)

	if len(nonce) >= 12 {
		counter := binary.BigEndian.Uint64(nonce[4:12])
		if !peer.ValidateReplay(counter) {
			pool.Put(plaintextBufPtr)
			return
		}
	}

	currentEP := peer.GetEndpoint()
	shouldUpdate := false
	if currentEP == nil {
		shouldUpdate = true
	} else if currentEP.Port != rAddr.Port || !currentEP.IP.Equal(rAddr.IP) {
		shouldUpdate = true
	}
	
	if shouldUpdate {
		newEP := &net.UDPAddr{IP: make(net.IP, len(rAddr.IP)), Port: rAddr.Port}
		copy(newEP.IP, rAddr.IP)
		peer.SetEndpoint(newEP)
	}

	peer.UpdateTimestamps(true) 

	if len(plaintext) == 0 {
		pool.Put(plaintextBufPtr)
		return
	}

	atomic.AddUint64(&peer.BytesRx, uint64(len(plaintext)))

	dstIP := netutil.ExtractDstIP(plaintext)
	
	// --- ENRUTAMIENTO CRÍTICO (Gateway / Site-to-Site Fix) ---

	// 1. ¿Es para MÍ (VIP)? -> Aceptamos incondicionalmente.
	if dstIP == e.localVIP {
		writeToTun(e, plaintext, plaintextBufPtr)
		return
	}

	// 2. ¿Es para OTRO peer conocido en la malla? -> Relay.
	targetPeer := e.router.Lookup(dstIP)
	if targetPeer != nil {
		e.sendRelay(plaintext, plaintextBufPtr, targetPeer)
		return
	}

	// 3. ¿No es VIP ni es Peer? -> GATEWAY MODE
	writeToTun(e, plaintext, plaintextBufPtr)
}

func writeToTun(e *Engine, plaintext []byte, buff *pool.Buff) {
	// Offset write para cabeceras TUN
	packetLen := len(plaintext)
	fullPacket := buff[:TunHeadroom+packetLen]

	if _, err := e.ifce.Write([][]byte{fullPacket}, TunHeadroom); err != nil {
		if e.cfg.Debug {
			log.Printf("❌ TUN Write Error: %v", err)
		}
	}
	pool.Put(buff)
}

func (e *Engine) sendRelay(plaintext []byte, buff *pool.Buff, peer *PeerInfo) {
	endpoint := peer.GetEndpoint()
	aead := peer.GetAEAD()

	if endpoint == nil || aead == nil {
		pool.Put(buff)
		return
	}

	outBufPtr := pool.Get()
	outBuf := outBufPtr[:]
	
	offset := protocol.HeaderSize
	
	copy(outBuf[offset:], plaintext)
	pool.Put(buff)

	// OPTIMIZACION (STACK): Nonce en stack
	var nonceArr [protocol.NonceSize]byte
	nonceBuf := nonceArr[:]
	
	copy(nonceBuf[0:4], []byte{0xCA, 0xFE, 0xBA, 0xBE})
	ctr := atomic.AddUint64(&e.txCounter, 1)
	binary.BigEndian.PutUint64(nonceBuf[4:], ctr)

	protocol.EncodeDataHeader(outBuf[:offset], e.localVIP, nonceBuf)

	encrypted := aead.Seal(outBuf[offset:offset], nonceBuf, outBuf[offset:offset+len(plaintext)], nil)
	totalLen := offset + len(encrypted)

	atomic.AddUint64(&peer.BytesTx, uint64(len(encrypted)))
	
	req := txRequest{
		Data: outBuf[:totalLen],
		Buff: outBufPtr,
		Addr: endpoint,
	}

	newBatch := txBatchPool.Get().(*TxBatch)
	newBatch.Reqs[0] = req
	newBatch.Len = 1
	
	select {
	case e.txCh <- newBatch:
	default:
		pool.Put(outBufPtr)
		txBatchPool.Put(newBatch)
		if e.cfg.Debug {
			log.Println("⚠️ DROP (Relay): TX Channel Full")
		}
	}
}
