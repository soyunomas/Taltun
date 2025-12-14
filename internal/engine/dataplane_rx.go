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

// tunBatcher encapsula el estado de escritura por lotes hacia la interfaz TUN.
type tunBatcher struct {
	datas [][]byte
	refs  []*pool.Buff
	count int
}

func (tb *tunBatcher) reset() {
	tb.count = 0
}

func (tb *tunBatcher) add(data []byte, ref *pool.Buff) {
	if tb.count < BatchSize {
		tb.datas[tb.count] = data
		tb.refs[tb.count] = ref
		tb.count++
	} else {
		// Safety fallback: si el batch explota, devolver al pool para evitar leak
		pool.Put(ref)
	}
}

func (e *Engine) loopUdpBatchToTun(conn *ipv4.PacketConn, sockIdx int) error {
	log.Printf("⚡ Batch RX Worker #%d iniciado (Optimized: TUN Write Batching)", sockIdx)
	
	// Estructuras de Lectura (UDP Input)
	msgs := make([]ipv4.Message, BatchSize)
	buffers := make([]*pool.Buff, BatchSize)
	
	for i := range msgs {
		buffers[i] = pool.Get()
		msgs[i].Buffers = [][]byte{buffers[i][:]}
	}

	// Estructuras de Escritura (TUN Output)
	tBatch := &tunBatcher{
		datas: make([][]byte, BatchSize),
		refs:  make([]*pool.Buff, BatchSize),
		count: 0,
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

		// 1. Procesar CPU (Desencriptar + Routing)
		tBatch.reset()

		for i := 0; i < nMsgs; i++ {
			msg := msgs[i]
			n := msg.N
			rAddr := msg.Addr.(*net.UDPAddr)
			packet := buffers[i][:n]

			e.processOnePacket(packet, buffers[i], rAddr, sockIdx, &lastVIP, &lastPeer, tBatch)
			
			// Reponer buffer
			buffers[i] = pool.Get()
			msgs[i].Buffers[0] = buffers[i][:]
		}

		// 2. IO Burst (Escribir a TUN)
		if tBatch.count > 0 {
			// Write espera [][]byte. Pasamos el slice hasta count.
			if _, err := e.ifce.Write(tBatch.datas[:tBatch.count], TunHeadroom); err != nil {
				if e.cfg.Debug {
					log.Printf("❌ TUN Batch Write Error: %v", err)
				}
			}

			// Devolver buffers al pool tras la escritura
			for k := 0; k < tBatch.count; k++ {
				pool.Put(tBatch.refs[k])
				tBatch.refs[k] = nil
			}
		}
	}
}

func (e *Engine) processOnePacket(pkt []byte, originalBuff *pool.Buff, rAddr *net.UDPAddr, sockIdx int, lastVIP *uint32, lastPeer **PeerInfo, tb *tunBatcher) {
	if len(pkt) < 1 {
		pool.Put(originalBuff) 
		return
	}
	msgType := pkt[0]

	// --- PATH CONTROL (Handshake / Cookie) ---
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

	// --- PATH DATA ---
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
	
	// Decrypt leaving headroom
	plaintext, err := peer.Open(plaintextBufPtr[TunHeadroom:TunHeadroom], nonce, ciphertext, nil)
	if err != nil {
		pool.Put(plaintextBufPtr)
		pool.Put(originalBuff)
		return
	}
	
	pool.Put(originalBuff) // Free UDP buffer

	if len(nonce) >= 12 {
		counter := binary.BigEndian.Uint64(nonce[4:12])
		if !peer.ValidateReplay(counter) {
			pool.Put(plaintextBufPtr)
			return
		}
	}

	// Endpoint update logic
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
	
	// --- ROUTING DECISION ---

	// 1. Local Delivery
	if dstIP == e.localVIP {
		packetLen := len(plaintext)
		// Apuntamos al inicio del buffer con Headroom incluido para el driver TUN
		fullPacket := plaintextBufPtr[:TunHeadroom+packetLen]
		tb.add(fullPacket, plaintextBufPtr)
		return
	}

	// 2. Relay (Forward to another peer)
	targetPeer := e.router.Lookup(dstIP)
	if targetPeer != nil {
		e.sendRelay(plaintext, plaintextBufPtr, targetPeer)
		return
	}

	// 3. Gateway / Default Route (Deliver to TUN)
	packetLen := len(plaintext)
	fullPacket := plaintextBufPtr[:TunHeadroom+packetLen]
	tb.add(fullPacket, plaintextBufPtr)
}

// sendRelay re-encripta un paquete recibido y lo pone en la cola de salida TX.
// Se usa para tráfico Client-to-Client.
func (e *Engine) sendRelay(plaintext []byte, buff *pool.Buff, peer *PeerInfo) {
	endpoint := peer.GetEndpoint()
	aead := peer.GetAEAD()

	// Si no hay ruta válida, descartamos y liberamos memoria.
	if endpoint == nil || aead == nil {
		pool.Put(buff)
		return
	}

	// Nuevo buffer para el paquete de salida
	outBufPtr := pool.Get()
	outBuf := outBufPtr[:]
	
	offset := protocol.HeaderSize
	
	// Copiamos el plaintext al nuevo buffer dejando espacio para el header
	copy(outBuf[offset:], plaintext)
	
	// Liberamos el buffer de entrada (plaintext original) ya que hemos hecho copia
	pool.Put(buff)

	// Generar Nonce en Stack
	var nonceArr [protocol.NonceSize]byte
	nonceBuf := nonceArr[:]
	
	copy(nonceBuf[0:4], []byte{0xCA, 0xFE, 0xBA, 0xBE})
	ctr := atomic.AddUint64(&e.txCounter, 1)
	binary.BigEndian.PutUint64(nonceBuf[4:], ctr)

	protocol.EncodeDataHeader(outBuf[:offset], e.localVIP, nonceBuf)

	// Encriptar
	encrypted := aead.Seal(outBuf[offset:offset], nonceBuf, outBuf[offset:offset+len(plaintext)], nil)
	totalLen := offset + len(encrypted)

	atomic.AddUint64(&peer.BytesTx, uint64(len(encrypted)))
	
	req := txRequest{
		Data: outBuf[:totalLen],
		Buff: outBufPtr,
		Addr: endpoint,
	}

	// Inyectar en el sistema de Batch TX
	newBatch := txBatchPool.Get().(*TxBatch)
	newBatch.Reqs[0] = req
	newBatch.Len = 1
	
	select {
	case e.txCh <- newBatch:
		// Enviado
	default:
		// Canal lleno, drop packet
		pool.Put(outBufPtr)
		txBatchPool.Put(newBatch)
		if e.cfg.Debug {
			log.Println("⚠️ DROP (Relay): TX Channel Full")
		}
	}
}
