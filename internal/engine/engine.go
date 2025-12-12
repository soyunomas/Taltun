package engine

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Soyunomas/taltun/internal/config"
	"github.com/Soyunomas/taltun/internal/session"
	"github.com/Soyunomas/taltun/pkg/cookie"
	"github.com/Soyunomas/taltun/pkg/crypto"
	"github.com/Soyunomas/taltun/pkg/netutil"
	"github.com/Soyunomas/taltun/pkg/pool"
	"github.com/Soyunomas/taltun/pkg/protocol"
	"github.com/Soyunomas/taltun/pkg/router"
	
	"golang.org/x/net/ipv4"
	"golang.zx2c4.com/wireguard/tun"
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

type TxBatch struct {
	Reqs [BatchSize]txRequest
	Len  int
}

var txBatchPool = sync.Pool{
	New: func() interface{} {
		return &TxBatch{}
	},
}

type PeerMap = map[uint32]*PeerInfo

type Engine struct {
	cfg   *config.Config
	
	ifce  tun.Device
	
	pconns []*ipv4.PacketConn
	rawConns []*net.UDPConn
	
	staticKey *crypto.KeyPair
	localVIP  uint32

	// Protection Modules
	cookieProtector *cookie.Protector

	// Routing & Peering
	peers        atomic.Pointer[PeerMap]
	router       *router.Router 
	peersWriteMu sync.Mutex

	handshakeCh chan HandshakeRequest
	txCh        chan *TxBatch
	
	txCounter   uint64
	closed atomic.Bool
}

type PeerInfo = session.Peer

func New(c *config.Config) (*Engine, error) {
	kp, err := crypto.NewKeyPairFromPrivate(c.SecretKey)
	if err != nil {
		return nil, err
	}
	
	myVIP := netutil.IPToUint32(c.LocalVIP)

	e := &Engine{
		cfg:             c,
		staticKey:       kp,
		localVIP:        myVIP,
		cookieProtector: cookie.NewProtector(),
		router:          router.New(),
		handshakeCh:     make(chan HandshakeRequest, 500),
		txCh:            make(chan *TxBatch, 128), 
	}

	initialPeers := make(PeerMap)
	e.peers.Store(&initialPeers)

	return e, nil
}

func (e *Engine) AddPeer(virtualIP net.IP, remoteAddr string, allowedIPs []string) error {
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

	e.peersWriteMu.Lock()
	defer e.peersWriteMu.Unlock()

	// 1. Añadir al Mapa (Identificación por VIP Header)
	oldMap := *e.peers.Load()
	newMap := make(PeerMap, len(oldMap)+1)
	for k, v := range oldMap {
		newMap[k] = v
	}
	newMap[vip] = p
	e.peers.Store(&newMap)

	// 2. Añadir al Router (LPM por Destination IP)
	// Siempre añadimos la VIP exacta (/32)
	e.router.Insert(fmt.Sprintf("%s/32", virtualIP.String()), p)

	// Añadir AllowedIPs adicionales (Subnets)
	for _, cidr := range allowedIPs {
		if err := e.router.Insert(cidr, p); err != nil {
			log.Printf("⚠️ Error añadiendo AllowedIP %s para peer %s: %v", cidr, virtualIP, err)
		} else {
			log.Printf("twisted_rightwards_arrows Route: %s -> Peer %s", cidr, virtualIP)
		}
	}

	log.Printf("🔗 Peer Configurado: VIP=%s Endpoint=%v AllowedIPs=%d", virtualIP, remoteAddr, len(allowedIPs))
	return nil
}

func (e *Engine) Initialize() error {
	dev, err := tun.CreateTUN(e.cfg.TunName, e.cfg.MTU)
	if err != nil {
		return fmt.Errorf("error creando TUN: %v", err)
	}
	e.ifce = dev

	ip := netutil.Uint32ToIP(e.localVIP)
	log.Printf("🔧 Configurando Interfaz %s: IP=%s/24 MTU=%d", e.cfg.TunName, ip, e.cfg.MTU)
	
	if err := netutil.AssignIP(e.cfg.TunName, ip); err != nil {
		dev.Close()
		return fmt.Errorf("fallo asignando IP: %v", err)
	}

	if len(e.cfg.Routes) > 0 {
		log.Printf("🛣️  Añadiendo rutas estáticas locales: %v", e.cfg.Routes)
		if err := netutil.AddRoutes(e.cfg.TunName, e.cfg.Routes); err != nil {
			dev.Close()
			return fmt.Errorf("fallo añadiendo rutas: %v", err)
		}
	}

	numCPU := runtime.NumCPU()
	e.pconns = make([]*ipv4.PacketConn, numCPU)
	e.rawConns = make([]*net.UDPConn, numCPU)
	
	log.Printf("⚙️ Inicializando %d sockets Batch UDP...", numCPU)

	for i := 0; i < numCPU; i++ {
		c, err := netutil.ListenUDPReusePort("udp", e.cfg.LocalAddr)
		if err != nil {
			dev.Close()
			return fmt.Errorf("error binding socket %d: %v", i, err)
		}
		e.rawConns[i] = c
		e.pconns[i] = ipv4.NewPacketConn(c)
	}

	return nil
}

func (e *Engine) Close() {
	if e.closed.Swap(true) {
		return
	}
	log.Println("🛑 Cerrando recursos (TUN/UDP)...")
	
	for _, c := range e.rawConns {
		c.Close()
	}
	
	if e.ifce != nil {
		e.ifce.Close()
	}
}

func (e *Engine) Run(ctx context.Context) error {
	errChan := make(chan error, len(e.pconns)+3)

	for i, pc := range e.pconns {
		idx := i
		pconn := pc
		go func() {
			errChan <- e.loopUdpBatchToTun(pconn, idx)
		}()
	}

	go func() { errChan <- e.loopTunReadAndEncrypt() }()
	go func() { errChan <- e.loopUdpBatchWrite() }()
	go func() { errChan <- e.housekeepingWorker(ctx) }() 
	
	go e.handshakeWorker()

	log.Printf("🚀 Engine Running (ROUTING V2): %d Cores | VIP: %s", 
		len(e.pconns), e.cfg.LocalVIP)
	
	// Trigger inicial
	currentPeers := *e.peers.Load()
	for _, p := range currentPeers {
		if p.GetEndpoint() != nil {
			go e.sendHandshakeInit(p)
		}
	}

	select {
	case <-ctx.Done():
		e.Close()
		return nil
	case err := <-errChan:
		if !e.closed.Load() {
			return err
		}
		return nil
	}
}

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
	defer pool.Put(pkt)

	nonceBuf := make([]byte, protocol.NonceSize)
	copy(nonceBuf[0:4], []byte{0xCA, 0xFE, 0xBA, 0xBE})
	ctr := atomic.AddUint64(&e.txCounter, 1)
	binary.BigEndian.PutUint64(nonceBuf[4:], ctr)

	protocol.EncodeDataHeader(pkt[:], e.localVIP, nonceBuf)
	
	encrypted := aead.Seal(pkt[protocol.HeaderSize:protocol.HeaderSize], nonceBuf, nil, nil)
	totalLen := protocol.HeaderSize + len(encrypted)

	if len(e.rawConns) > 0 {
		e.rawConns[0].WriteToUDP(pkt[:totalLen], endpoint)
		p.UpdateTimestamps(false)
	}
}

// --- DATAPLANE RX (UDP -> TUN + RELAY) ---

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

			// Pasamos el buffer completo para que si hay Relay, pueda ser reutilizado
			e.processOnePacket(packet, buffers[i], rAddr, sockIdx, &lastVIP, &lastPeer)
			
			// Siempre asignamos un nuevo buffer para la siguiente lectura
			buffers[i] = pool.Get()
			msgs[i].Buffers[0] = buffers[i][:]
		}
	}
}

func (e *Engine) processOnePacket(pkt []byte, originalBuff *pool.Buff, rAddr *net.UDPAddr, sockIdx int, lastVIP *uint32, lastPeer **PeerInfo) {
	if len(pkt) < 1 {
		pool.Put(originalBuff) // Descartar
		return
	}
	msgType := pkt[0]

	// 1. Manejo de Paquetes de Control
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

		// Copia necesaria porque el handshakeCh es asíncrono
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

	// 2. Manejo de Paquetes de Datos (Hot Path)
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

	// Decrypt
	plaintextBufPtr := pool.Get()
	
	plaintext, err := peer.Open(plaintextBufPtr[:0], nonce, ciphertext, nil)
	if err != nil {
		pool.Put(plaintextBufPtr)
		pool.Put(originalBuff)
		return
	}
	
	// Liberamos original (ciphertext)
	pool.Put(originalBuff)

	// Anti-Replay Protection
	if len(nonce) >= 12 {
		counter := binary.BigEndian.Uint64(nonce[4:12])
		if !peer.ValidateReplay(counter) {
			pool.Put(plaintextBufPtr)
			return
		}
	}

	currentEP := peer.GetEndpoint()
	if currentEP != rAddr { 
		if currentEP == nil || currentEP.String() != rAddr.String() {
			peer.SetEndpoint(rAddr)
		}
	}
	peer.UpdateTimestamps(true) // Recibido

	if len(plaintext) == 0 {
		pool.Put(plaintextBufPtr) // Keepalive, descartar
		return
	}

	atomic.AddUint64(&peer.BytesRx, uint64(len(plaintext)))

	// --- ROUTING V2: DECISIÓN DE ENRUTAMIENTO ---
	
	dstIP := netutil.ExtractDstIP(plaintext)
	
	// Caso A: El paquete es para MÍ
	if dstIP == e.localVIP {
		e.ifce.Write([][]byte{plaintext}, 0)
		pool.Put(plaintextBufPtr) // TUN hace copy, liberamos buffer
		return
	}

	// Caso B: El paquete es para OTRO (Relay / Forwarding)
	targetPeer := e.router.Lookup(dstIP)
	
	if targetPeer != nil {
		// Pasamos ownership de plaintextBufPtr a sendRelay
		e.sendRelay(plaintext, plaintextBufPtr, targetPeer)
		return
	}

	// Caso C: Desconocido (Drop)
	pool.Put(plaintextBufPtr)
}

// sendRelay re-encripta un paquete para un peer destino y lo mete en la cola de TX.
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
	
	// Copiamos plaintext (buffers pueden ser distintos)
	copy(outBuf[offset:], plaintext)
	
	// Liberamos el buffer de plaintext original (RX buffer)
	pool.Put(buff)

	nonceBuf := make([]byte, protocol.NonceSize) 
	copy(nonceBuf[0:4], []byte{0xCA, 0xFE, 0xBA, 0xBE})
	ctr := atomic.AddUint64(&e.txCounter, 1)
	binary.BigEndian.PutUint64(nonceBuf[4:], ctr)

	protocol.EncodeDataHeader(outBuf[:offset], e.localVIP, nonceBuf)

	// Encrypt
	encrypted := aead.Seal(outBuf[offset:offset], nonceBuf, outBuf[offset:offset+len(plaintext)], nil)
	totalLen := offset + len(encrypted)

	atomic.AddUint64(&peer.BytesTx, uint64(len(encrypted)))
	
	req := txRequest{
		Data: outBuf[:totalLen],
		Buff: outBufPtr,
		Addr: endpoint,
	}

	// Creamos un lote unitario y lo enviamos
	// Esto es mucho más simple y evita el error anterior de leer del canal
	newBatch := txBatchPool.Get().(*TxBatch)
	newBatch.Reqs[0] = req
	newBatch.Len = 1
	
	e.txCh <- newBatch
}

// --- DATAPLANE TX SPLIT (TUN -> BATCH -> CHANNEL -> UDP) ---

func (e *Engine) loopTunReadAndEncrypt() error {
	nonceBuf := make([]byte, protocol.NonceSize)
	copy(nonceBuf[0:4], []byte{0xCA, 0xFE, 0xBA, 0xBE})
	
	const TunBatchSize = BatchSize 
	
	buffsPtrs := make([]*pool.Buff, TunBatchSize)
	buffs := make([][]byte, TunBatchSize)
	sizes := make([]int, TunBatchSize)

	for i := 0; i < TunBatchSize; i++ {
		buffsPtrs[i] = pool.Get()
		buffs[i] = buffsPtrs[i][:]
	}
	
	offset := protocol.HeaderSize
	var lastDstIP uint32
	var lastPeer *PeerInfo

	currentBatch := txBatchPool.Get().(*TxBatch)
	currentBatch.Len = 0

	for {
		n, err := e.ifce.Read(buffs, sizes, offset)
		if err != nil {
			if e.closed.Load() {
				return nil
			}
			return fmt.Errorf("tun read error: %v", err)
		}

		for i := 0; i < n; i++ {
			size := sizes[i]
			if size == 0 {
				continue
			}
			
			packetData := buffs[i][offset : offset+size]
			dstIP := netutil.ExtractDstIP(packetData)
			
			var peer *PeerInfo
			
			if lastPeer != nil && lastDstIP == dstIP {
				peer = lastPeer
			} else {
				peer = e.router.Lookup(dstIP)

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
			copy(outBuf[offset:], packetData)

			ctr := atomic.AddUint64(&e.txCounter, 1)
			binary.BigEndian.PutUint64(nonceBuf[4:], ctr)
			protocol.EncodeDataHeader(outBuf[:offset], e.localVIP, nonceBuf)

			encrypted := aead.Seal(outBuf[offset:offset], nonceBuf, outBuf[offset:offset+size], nil)
			totalLen := offset + len(encrypted)

			atomic.AddUint64(&peer.BytesTx, uint64(len(encrypted)))
			peer.UpdateTimestamps(false) 

			req := txRequest{
				Data: outBuf[:totalLen],
				Buff: outBufPtr,
				Addr: endpoint,
			}
			
			currentBatch.Reqs[currentBatch.Len] = req
			currentBatch.Len++

			if currentBatch.Len == BatchSize {
				e.txCh <- currentBatch
				currentBatch = txBatchPool.Get().(*TxBatch)
				currentBatch.Len = 0
			}
		}

		if currentBatch.Len > 0 {
			e.txCh <- currentBatch
			currentBatch = txBatchPool.Get().(*TxBatch)
			currentBatch.Len = 0
		}
	}
}

func (e *Engine) loopUdpBatchWrite() error {
	msgs := make([]ipv4.Message, BatchSize)
	var connIdx int

	for {
		batch := <-e.txCh
		
		count := batch.Len
		if count == 0 {
			txBatchPool.Put(batch)
			continue
		}

		for i := 0; i < count; i++ {
			msgs[i].Buffers = [][]byte{batch.Reqs[i].Data}
			msgs[i].Addr = batch.Reqs[i].Addr
		}

		conn := e.pconns[connIdx]
		connIdx = (connIdx + 1) % len(e.pconns)

		_, err := conn.WriteBatch(msgs[:count], 0)
		if err != nil {
			if e.cfg.Debug {
				log.Printf("writebatch error: %v", err)
			}
			if e.closed.Load() {
				return nil
			}
		}

		for i := 0; i < count; i++ {
			pool.Put(batch.Reqs[i].Buff)
			batch.Reqs[i].Buff = nil
			batch.Reqs[i].Data = nil
			msgs[i].Buffers = nil
		}

		txBatchPool.Put(batch)
	}
}

// --- CONTROL PLANE ---

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
