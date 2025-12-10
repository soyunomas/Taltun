package engine

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/Soyunomas/taltun/internal/config"
	"github.com/Soyunomas/taltun/internal/session"
	"github.com/Soyunomas/taltun/pkg/crypto"
	"github.com/Soyunomas/taltun/pkg/netutil"
	"github.com/Soyunomas/taltun/pkg/pool"
	"github.com/Soyunomas/taltun/pkg/protocol"
	"github.com/songgao/water"
	"golang.org/x/net/ipv4"
)

// BatchSize define cuántos paquetes leemos/escribimos de golpe.
const BatchSize = 64

type HandshakeRequest struct {
	RemoteAddr *net.UDPAddr
	Packet     []byte
	ConnIndex  int
}

// txRequest representa un paquete ya encriptado listo para enviar.
type txRequest struct {
	Data []byte       // Slice sobre el buffer del pool
	Buff *pool.Buff   // Puntero original para devolverlo al pool
	Addr *net.UDPAddr // Destino
}

type Engine struct {
	cfg   *config.Config
	ifce  *water.Interface
	
	// Usamos ipv4.PacketConn para tener acceso a ReadBatch y WriteBatch
	pconns []*ipv4.PacketConn
	// Guardamos la referencia al UDPConn original
	rawConns []*net.UDPConn
	
	staticKey *crypto.KeyPair
	localVIP  uint32

	peers   map[uint32]*PeerInfo
	peersMu sync.RWMutex

	handshakeCh chan HandshakeRequest
	
	// Canal para desacoplar lectura de TUN y escritura UDP (Batching TX)
	txCh chan txRequest

	txCounter   uint64
}

type PeerInfo = session.Peer

func New(c *config.Config) (*Engine, error) {
	kp, err := crypto.NewKeyPairFromPrivate(c.SecretKey)
	if err != nil {
		return nil, err
	}
	
	myVIP := netutil.IPToUint32(c.LocalVIP)

	return &Engine{
		cfg:         c,
		staticKey:   kp,
		localVIP:    myVIP,
		peers:       make(map[uint32]*PeerInfo),
		handshakeCh: make(chan HandshakeRequest, 500),
		// Buffer grande para absorber ráfagas del TUN antes de enviar
		txCh:        make(chan txRequest, 1024), 
	}, nil
}

func (e *Engine) AddPeer(virtualIP net.IP, remoteAddr string) error {
	vip := netutil.IPToUint32(virtualIP)
	if vip == 0 {
		return fmt.Errorf("ip virtual invalida")
	}

	var udpAddr *net.UDPAddr
	var err error
	
	if remoteAddr != "" {
		udpAddr, err = net.ResolveUDPAddr("udp", remoteAddr)
		if err != nil {
			return err
		}
	}

	p := session.NewPeer(vip, udpAddr)

	e.peersMu.Lock()
	e.peers[vip] = p
	e.peersMu.Unlock()

	log.Printf("🔗 Peer Configurado: VIP=%s Endpoint=%v", virtualIP, remoteAddr)
	return nil
}

func (e *Engine) Initialize() error {
	cfg := water.Config{ DeviceType: water.TUN }
	cfg.PlatformSpecificParams.Name = e.cfg.TunName
	
	ifce, err := water.New(cfg)
	if err != nil {
		return fmt.Errorf("error creando TUN: %v", err)
	}
	e.ifce = ifce

	numCPU := runtime.NumCPU()
	e.pconns = make([]*ipv4.PacketConn, numCPU)
	e.rawConns = make([]*net.UDPConn, numCPU)
	
	log.Printf("⚙️ Inicializando %d sockets Batch UDP...", numCPU)

	for i := 0; i < numCPU; i++ {
		c, err := netutil.ListenUDPReusePort("udp", e.cfg.LocalAddr)
		if err != nil {
			return fmt.Errorf("error binding socket %d: %v", i, err)
		}
		e.rawConns[i] = c
		e.pconns[i] = ipv4.NewPacketConn(c)
	}

	return nil
}

func (e *Engine) Run() error {
	errChan := make(chan error, len(e.pconns)+2)

	// 1. Start Batch RX Workers (UDP -> TUN)
	for i, pc := range e.pconns {
		idx := i
		pconn := pc
		go func() {
			errChan <- e.loopUdpBatchToTun(pconn, idx)
		}()
	}

	// 2. Start TX Split Pipeline (TUN -> UDP)
	go func() { errChan <- e.loopTunReadAndEncrypt() }()
	go func() { errChan <- e.loopUdpBatchWrite() }()
	
	// 3. Start Control Plane
	go e.handshakeWorker()

	log.Printf("🚀 Engine Running (VECTORIZED TX/RX): %d Cores | VIP: %s", 
		len(e.pconns), e.cfg.LocalVIP)
	
	// 4. Initial Handshakes
	e.peersMu.RLock()
	for _, p := range e.peers {
		if p.GetEndpoint() != nil {
			go e.sendHandshakeInit(p)
		}
	}
	e.peersMu.RUnlock()

	return <-errChan
}

// --- DATAPLANE RX (UDP -> TUN) ---

func (e *Engine) loopUdpBatchToTun(conn *ipv4.PacketConn, sockIdx int) error {
	log.Printf("⚡ Batch RX Worker #%d iniciado", sockIdx)
	
	msgs := make([]ipv4.Message, BatchSize)
	buffers := make([]*pool.Buff, BatchSize)
	
	for i := range msgs {
		buffers[i] = pool.Get()
		msgs[i].Buffers = [][]byte{buffers[i][:]}
	}

	// Hot-Path Variables: Cache local de Peer
	var lastVIP uint32
	var lastPeer *PeerInfo

	for {
		nMsgs, err := conn.ReadBatch(msgs, 0)
		if err != nil {
			return fmt.Errorf("readbatch error: %v", err)
		}

		for i := 0; i < nMsgs; i++ {
			msg := msgs[i]
			n := msg.N
			rAddr := msg.Addr.(*net.UDPAddr)
			packet := buffers[i][:n]

			// Pasamos punteros a la caché para actualizarla si cambia
			e.processOnePacket(packet, rAddr, sockIdx, &lastVIP, &lastPeer)
			
			msgs[i].Buffers[0] = buffers[i][:]
		}
	}
}

// processOnePacket optimizado con Peer Caching
func (e *Engine) processOnePacket(pkt []byte, rAddr *net.UDPAddr, sockIdx int, lastVIP *uint32, lastPeer **PeerInfo) {
	if len(pkt) < 1 {
		return
	}
	msgType := pkt[0]

	// --- Control Plane (Sin cambios) ---
	if msgType == protocol.MsgTypeHandshakeInit || msgType == protocol.MsgTypeHandshakeResp {
		handshakePkt := make([]byte, len(pkt))
		copy(handshakePkt, pkt)
		
		select {
		case e.handshakeCh <- HandshakeRequest{
			RemoteAddr: rAddr, 
			Packet: handshakePkt,
			ConnIndex: sockIdx,
		}:
		default:
		}
		return
	}

	// --- Data Plane ---
	_, senderVIP, nonce, ciphertext, err := protocol.ParseHeader(pkt)
	if err != nil {
		return
	}

	// --- OPTIMIZACIÓN: Peer Cache Lookup ---
	// Si el paquete viene del mismo VIP que el anterior, nos ahorramos el RLock y el Map Lookup
	var peer *PeerInfo
	
	if *lastPeer != nil && *lastVIP == senderVIP {
		// HIT de Caché
		peer = *lastPeer
	} else {
		// MISS de Caché: Buscar y actualizar
		e.peersMu.RLock()
		peer = e.peers[senderVIP]
		e.peersMu.RUnlock()
		
		if peer != nil {
			// Actualizar caché para el siguiente paquete
			*lastVIP = senderVIP
			*lastPeer = peer
		}
	}

	if peer == nil {
		return
	}

	aead := peer.GetAEAD()
	if aead == nil {
		return
	}

	// Decrypt
	outBufPtr := pool.Get()
	defer pool.Put(outBufPtr)
	
	plaintext, err := aead.Open(outBufPtr[:0], nonce, ciphertext, nil)
	if err != nil {
		return
	}

	// NAT Update (Solo si cambia, para no bloquear con SetEndpoint)
	currentEP := peer.GetEndpoint()
	// Comprobación rápida de punteros primero, luego string
	if currentEP != rAddr { 
		// Es probable que rAddr sea un objeto nuevo cada vez en ReadBatch, así que
		// comparamos IPs y Puertos si los objetos son distintos en memoria.
		// Para evitar overhead de String(), comparamos campos básicos si es posible,
		// o asumimos que el endpoint es estable.
		// En este hot-path, simplificamos: Solo actualizamos si el sistema de control lo pide
		// o usamos una lógica más laxa. Por ahora lo dejamos igual pero con el ojo puesto.
		if currentEP == nil || currentEP.String() != rAddr.String() {
			peer.SetEndpoint(rAddr)
		}
	}
	
	atomic.AddUint64(&peer.BytesRx, uint64(len(plaintext)))

	// Write TUN
	e.ifce.Write(plaintext)
}

// --- DATAPLANE TX SPLIT (TUN -> CHANNEL -> UDP BATCH) ---

func (e *Engine) loopTunReadAndEncrypt() error {
	nonceBuf := make([]byte, protocol.NonceSize)
	copy(nonceBuf[0:4], []byte{0xCA, 0xFE, 0xBA, 0xBE})
	
	tunBufPtr := pool.Get()
	tunBuf := tunBufPtr[:]
	defer pool.Put(tunBufPtr)

	offset := protocol.HeaderSize

	// Cache para TX también
	var lastDstIP uint32
	var lastPeer *PeerInfo

	for {
		n, err := e.ifce.Read(tunBuf[offset:])
		if err != nil {
			return fmt.Errorf("read tun error: %v", err)
		}

		dstIP := netutil.ExtractDstIP(tunBuf[offset : offset+n])
		
		// Optimización Caché TX
		var peer *PeerInfo
		if lastPeer != nil && lastDstIP == dstIP {
			peer = lastPeer
		} else {
			e.peersMu.RLock()
			peer = e.peers[dstIP]
			e.peersMu.RUnlock()
			if peer != nil {
				lastDstIP = dstIP
				lastPeer = peer
			}
		}

		if peer == nil {
			continue
		}

		endpoint := peer.GetEndpoint()
		aead := peer.GetAEAD()

		if endpoint == nil || aead == nil {
			continue
		}

		outBufPtr := pool.Get()
		outBuf := outBufPtr[:]
		copy(outBuf[offset:], tunBuf[offset:offset+n])

		ctr := atomic.AddUint64(&e.txCounter, 1)
		binary.BigEndian.PutUint64(nonceBuf[4:], ctr)

		protocol.EncodeDataHeader(outBuf[:offset], e.localVIP, nonceBuf)

		encrypted := aead.Seal(outBuf[offset:offset], nonceBuf, outBuf[offset:offset+n], nil)
		totalLen := offset + len(encrypted)

		atomic.AddUint64(&peer.BytesTx, uint64(len(encrypted)))

		req := txRequest{
			Data: outBuf[:totalLen],
			Buff: outBufPtr,
			Addr: endpoint,
		}

		select {
		case e.txCh <- req:
		default:
			pool.Put(outBufPtr)
		}
	}
}

func (e *Engine) loopUdpBatchWrite() error {
	msgs := make([]ipv4.Message, BatchSize)
	reqs := make([]txRequest, BatchSize)
	var connIdx int

	for {
		req := <-e.txCh
		
		reqs[0] = req
		msgs[0].Buffers = [][]byte{req.Data}
		msgs[0].Addr = req.Addr
		count := 1

	FillBatch:
		for count < BatchSize {
			select {
			case r := <-e.txCh:
				reqs[count] = r
				msgs[count].Buffers = [][]byte{r.Data}
				msgs[count].Addr = r.Addr
				count++
			default:
				break FillBatch
			}
		}

		conn := e.pconns[connIdx]
		connIdx = (connIdx + 1) % len(e.pconns)

		_, err := conn.WriteBatch(msgs[:count], 0)
		if err != nil && e.cfg.Debug {
			log.Printf("writebatch error: %v", err)
		}

		for i := 0; i < count; i++ {
			pool.Put(reqs[i].Buff)
			reqs[i].Buff = nil
			reqs[i].Data = nil
			msgs[i].Buffers = nil
		}
	}
}

// --- CONTROL PLANE (Sin cambios) ---

func (e *Engine) handshakeWorker() {
	for req := range e.handshakeCh {
		e.processHandshake(req)
	}
}

func (e *Engine) processHandshake(req HandshakeRequest) {
	senderVIP, pubKey, err := protocol.ParseHandshake(req.Packet)
	if err != nil {
		return
	}

	e.peersMu.RLock()
	peer, exists := e.peers[senderVIP]
	e.peersMu.RUnlock()

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
	e.sendHandshakePacket(e.localVIP, protocol.MsgTypeHandshakeInit, e.staticKey.Public[:], p.GetEndpoint())
}

func (e *Engine) sendHandshakeResp(p *PeerInfo, addr *net.UDPAddr) {
	e.sendHandshakePacket(e.localVIP, protocol.MsgTypeHandshakeResp, e.staticKey.Public[:], addr)
}

func (e *Engine) sendHandshakePacket(senderVIP uint32, msgType uint8, pubKey []byte, addr *net.UDPAddr) {
	if addr == nil {
		return
	}
	pkt := pool.Get()
	defer pool.Put(pkt)

	n, _ := protocol.EncodeHandshake(pkt[:], msgType, senderVIP, pubKey)
	
	if len(e.rawConns) > 0 {
		e.rawConns[0].WriteToUDP(pkt[:n], addr)
	}
}
