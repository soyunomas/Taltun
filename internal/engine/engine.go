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

// TunHeadroom: Espacio reservado al inicio del buffer para que el driver TUN
// escriba sus cabeceras (Packet Info) sin realocar memoria.
const TunHeadroom = 16

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
		txCh:            make(chan *TxBatch, 256), 
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

	oldMap := *e.peers.Load()
	newMap := make(PeerMap, len(oldMap)+1)
	for k, v := range oldMap {
		newMap[k] = v
	}
	newMap[vip] = p
	e.peers.Store(&newMap)

	e.router.Insert(fmt.Sprintf("%s/32", virtualIP.String()), p)

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
	// Si el paquete llegó hasta aquí autenticado, es porque el servidor nos lo envió
	// confiando en que está en nuestra red local (AllowedIPs en servidor).
	// Lo escribimos en TUN y que el Kernel decida si lo enruta a la LAN.
	
	// Nota: Un filtro de seguridad extra aquí sería ideal, pero para V10.0 con esto basta.
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

	nonceBuf := make([]byte, protocol.NonceSize) 
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

// --- DATAPLANE TX SPLIT (TUN -> BATCH -> CHANNEL -> UDP) ---

func (e *Engine) loopTunReadAndEncrypt() error {
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
			
			if dstIP == 0 {
				continue
			}
			
			var peer *PeerInfo
			
			if lastPeer != nil && lastDstIP == dstIP {
				peer = lastPeer
			} else {
				peer = e.router.Lookup(dstIP)

				if peer != nil {
					lastDstIP = dstIP
					lastPeer = peer
				} else {
					if e.cfg.Debug {
						// log.Printf("❌ DROP TX: No ruta para %s", netutil.Uint32ToIP(dstIP))
					}
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

			nonceBuf := make([]byte, protocol.NonceSize)
			copy(nonceBuf[0:4], []byte{0xCA, 0xFE, 0xBA, 0xBE})

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
				e.sendBatchSafe(currentBatch)
				currentBatch = txBatchPool.Get().(*TxBatch)
				currentBatch.Len = 0
			}
		}

		if currentBatch.Len > 0 {
			e.sendBatchSafe(currentBatch)
			currentBatch = txBatchPool.Get().(*TxBatch)
			currentBatch.Len = 0
		}
	}
}

func (e *Engine) sendBatchSafe(batch *TxBatch) {
	select {
	case e.txCh <- batch:
		// OK
	default:
		for i := 0; i < batch.Len; i++ {
			pool.Put(batch.Reqs[i].Buff)
		}
		txBatchPool.Put(batch)
		if e.cfg.Debug {
			log.Println("⚠️ DROP TX: Channel Full")
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

		n, err := conn.WriteBatch(msgs[:count], 0)
		if err != nil {
			if e.cfg.Debug {
				log.Printf("writebatch error: %v", err)
			}
			if e.closed.Load() {
				return nil
			}
		} else if n < count && e.cfg.Debug {
			log.Printf("⚠️ WriteBatch Parcial: %d/%d enviados", n, count)
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
