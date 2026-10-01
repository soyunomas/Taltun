package engine

import (
	"context"
	"encoding/binary"
	"encoding/hex"
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
	done        chan struct{}
	wg          sync.WaitGroup
	closed      atomic.Bool
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
		done:            make(chan struct{}),
	}

	initialPeers := make(PeerMap)
	e.peers.Store(&initialPeers)

	return e, nil
}

func (e *Engine) AddPeer(virtualIP net.IP, remoteAddr string, publicKeyHex string, allowedIPs []string, lighthouse bool) error {
	vip := netutil.IPToUint32(virtualIP)
	if vip == 0 {
		return fmt.Errorf("ip virtual invalida")
	}

	publicKeyBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return fmt.Errorf("public key invalida para %s: %w", virtualIP, err)
	}
	if len(publicKeyBytes) != crypto.KeySize {
		return fmt.Errorf("public key invalida para %s: esperado %d bytes, recibido %d", virtualIP, crypto.KeySize, len(publicKeyBytes))
	}
	var publicKey [crypto.KeySize]byte
	copy(publicKey[:], publicKeyBytes)

	var udpAddr *net.UDPAddr
	if remoteAddr != "" {
		udpAddr, err = net.ResolveUDPAddr("udp", remoteAddr)
		if err != nil {
			return err
		}
	}

	p := session.NewPeer(vip, udpAddr, publicKey)
	p.SetLighthouse(lighthouse)
	if err := p.SetAllowedSources(allowedIPs); err != nil {
		return fmt.Errorf("allowed_ips invalidas para %s: %w", virtualIP, err)
	}

	e.peersWriteMu.Lock()
	defer e.peersWriteMu.Unlock()

	oldMap := *e.peers.Load()
	newMap := make(PeerMap, len(oldMap)+1)
	for k, v := range oldMap {
		newMap[k] = v
	}
	newMap[vip] = p
	e.peers.Store(&newMap)

	if udpAddr != nil {
		if err := e.router.Insert(fmt.Sprintf("%s/32", virtualIP.String()), p); err != nil {
			return fmt.Errorf("ruta VIP invalida para %s: %w", virtualIP, err)
		}
	}

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

func (e *Engine) promotePeerRoute(p *PeerInfo) {
	if p == nil || p.GetEndpoint() == nil {
		return
	}
	cidr := fmt.Sprintf("%s/32", netutil.Uint32ToIP(p.VirtualIP))
	if err := e.router.Insert(cidr, p); err != nil {
		if e.cfg.Debug {
			log.Printf("no se pudo promocionar ruta %s: %v", cidr, err)
		}
	}
}

func (e *Engine) Initialize() error {
	if e.cfg.Mode != "lighthouse" {
		dev, err := tun.CreateTUN(e.cfg.TunName, e.cfg.MTU)
		if err != nil {
			return fmt.Errorf("error creando TUN: %v", err)
		}
		e.ifce = dev

		ip := netutil.Uint32ToIP(e.localVIP)
		log.Printf("🔧 Configurando Interfaz %s: IP=%s/24 MTU=%d", e.cfg.TunName, ip, e.cfg.MTU)

		if err := netutil.AssignIP(e.cfg.TunName, ip); err != nil {
			_ = dev.Close()
			e.ifce = nil
			return fmt.Errorf("fallo asignando IP: %v", err)
		}

		if len(e.cfg.Routes) > 0 {
			log.Printf("🛣️  Añadiendo rutas estáticas locales: %v", e.cfg.Routes)
			if err := netutil.AddRoutes(e.cfg.TunName, e.cfg.Routes); err != nil {
				_ = dev.Close()
				e.ifce = nil
				return fmt.Errorf("fallo añadiendo rutas: %v", err)
			}
		}
	} else {
		log.Println("💡 Iniciando en modo lighthouse sin interfaz TUN")
	}

	numCPU := e.cfg.Workers
	if numCPU <= 0 {
		numCPU = runtime.NumCPU()
	}
	e.pconns = make([]*ipv4.PacketConn, numCPU)
	e.rawConns = make([]*net.UDPConn, numCPU)

	for i := 0; i < numCPU; i++ {
		c, err := netutil.ListenUDPReusePort("udp", e.cfg.LocalAddr)
		if err != nil {
			for _, existing := range e.rawConns {
				if existing != nil {
					_ = existing.Close()
				}
			}
			if e.ifce != nil {
				_ = e.ifce.Close()
				e.ifce = nil
			}
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

	close(e.done)
	if e.cookieProtector != nil {
		e.cookieProtector.Close()
	}
	for _, c := range e.rawConns {
		if c != nil {
			_ = c.Close()
		}
	}
	if e.ifce != nil {
		_ = e.ifce.Close()
	}
}

func (e *Engine) Run(ctx context.Context) error {
	errChan := make(chan error, len(e.pconns)+4)
	start := func(fn func() error) {
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			if err := fn(); err != nil {
				select {
				case errChan <- err:
				case <-e.done:
				}
			}
		}()
	}

	for i, pc := range e.pconns {
		idx := i
		pconn := pc
		start(func() error { return e.loopUdpBatchToTun(pconn, idx) })
	}
	start(e.loopUdpBatchWrite)
	start(func() error { return e.housekeepingWorker(ctx) })

	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		e.handshakeWorker()
	}()

	if e.cfg.Mode != "lighthouse" {
		start(e.loopTunReadAndEncrypt)
	}

	log.Printf("🚀 Engine Running (%s): %d Cores | VIP: %s", e.cfg.Mode, len(e.pconns), e.cfg.LocalVIP)

	currentPeers := *e.peers.Load()
	for _, p := range currentPeers {
		if p.GetEndpoint() != nil {
			e.sendHandshakeInit(p)
		}
	}

	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-errChan:
	case <-e.done:
	}

	e.Close()
	e.wg.Wait()
	return runErr
}

// --- HOUSEKEEPING (Rekey + Keepalives) ---

func (e *Engine) housekeepingWorker(ctx context.Context) error {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-e.done:
			return nil
		case <-ticker.C:
			currentPeers := *e.peers.Load()
			for _, p := range currentPeers {
				if p.NeedsHandshake() {
					e.sendHandshakeInit(p)
				}
				if p.NeedsKeepalive() {
					e.sendKeepalive(p)
				}
			}
			e.reconcileLighthouseFallback(currentPeers)
		}
	}
}

func (e *Engine) reconcileLighthouseFallback(peers PeerMap) {
	if e.cfg.Mode == "lighthouse" {
		return
	}

	var lighthouse *PeerInfo
	for _, candidate := range peers {
		if candidate.IsLighthouse() && candidate.GetEndpoint() != nil && candidate.CurrentSessionID() != 0 {
			lighthouse = candidate
			break
		}
	}
	if lighthouse == nil {
		return
	}

	for _, p := range peers {
		if p == lighthouse || p.IsLighthouse() || p.GetEndpoint() == nil || p.CurrentSessionID() == 0 {
			continue
		}
		if !p.ReceiveStale(session.DirectFallbackTimeout) {
			continue
		}

		cidr := fmt.Sprintf("%s/32", netutil.Uint32ToIP(p.VirtualIP))
		if err := e.router.Insert(cidr, lighthouse); err == nil && e.cfg.Debug {
			log.Printf("↩️ Lighthouse fallback: %s via %s", netutil.Uint32ToIP(p.VirtualIP), netutil.Uint32ToIP(lighthouse.VirtualIP))
		}
	}
}

func (e *Engine) sendKeepalive(p *PeerInfo) {
	endpoint := p.GetEndpoint()
	sessionID, aead, counter, ok := p.NextOutbound()
	if !ok || endpoint == nil {
		return
	}

	pkt := pool.Get()
	defer pool.Put(pkt)

	var nonceBuf [protocol.NonceSize]byte
	binary.BigEndian.PutUint64(nonceBuf[4:], counter)
	if _, err := protocol.EncodeDataHeader(pkt[:], e.localVIP, sessionID, nonceBuf[:]); err != nil {
		return
	}

	encrypted := aead.Seal(
		pkt[protocol.HeaderSize:protocol.HeaderSize],
		nonceBuf[:],
		nil,
		pkt[:protocol.HeaderSize],
	)
	totalLen := protocol.HeaderSize + len(encrypted)

	if len(e.rawConns) > 0 {
		_, _ = e.rawConns[0].WriteToUDP(pkt[:totalLen], endpoint)
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

	if msgType == protocol.MsgTypePeerUpdate {
		e.processPeerUpdatePacket(pkt, rAddr)
		pool.Put(originalBuff)
		return
	}

	// 1. Control Plane
	if msgType == protocol.MsgTypeHandshakeInit || msgType == protocol.MsgTypeHandshakeResp || msgType == protocol.MsgTypeHandshakeFinish {
		underLoad := len(e.handshakeCh) > 250

		var cookie []byte
		if msgType != protocol.MsgTypeHandshakeFinish {
			h, err := protocol.ParseHandshake(pkt)
			if err != nil {
				pool.Put(originalBuff)
				return
			}
			cookie = h.Cookie
		}

		if underLoad && msgType == protocol.MsgTypeHandshakeInit {
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
					e.sendHandshakeInit(p)
					break
				}
			}
		}
		pool.Put(originalBuff)
		return
	}

	// 2. Data Plane (Hot Path)
	_, senderVIP, sessionID, nonce, ciphertext, err := protocol.ParseHeader(pkt)
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
	counter := binary.BigEndian.Uint64(nonce[4:12])
	plaintext, err := peer.Open(
		sessionID,
		plaintextBufPtr[TunHeadroom:TunHeadroom],
		nonce,
		ciphertext,
		pkt[:protocol.HeaderSize],
		counter,
	)
	if err != nil {
		if e.cfg.Debug {
			log.Printf("❌ RX OPEN sender=%s session=%016x counter=%d remote=%v err=%v",
				netutil.Uint32ToIP(senderVIP), sessionID, counter, rAddr, err)
		}
		pool.Put(plaintextBufPtr)
		pool.Put(originalBuff)
		return
	}

	pool.Put(originalBuff)

	if len(plaintext) > 0 {
		sourceIP := netutil.ExtractSrcIP(plaintext)
		if !peer.AllowsSource(sourceIP) {
			pool.Put(plaintextBufPtr)
			if e.cfg.Debug {
				log.Printf("DROP ingress: peer %s intento originar %s", netutil.Uint32ToIP(senderVIP), netutil.Uint32ToIP(sourceIP))
			}
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
	if !peer.IsLighthouse() && peer.VirtualIP != e.localVIP {
		// Any successfully authenticated packet from a non-lighthouse peer confirms
		// that the direct session is usable end-to-end.
		e.promotePeerRoute(peer)
	}

	if len(plaintext) == 0 {
		pool.Put(plaintextBufPtr)
		return
	}

	atomic.AddUint64(&peer.BytesRx, uint64(len(plaintext)))

	dstIP := netutil.ExtractDstIP(plaintext)
	if e.cfg.Debug {
		log.Printf("🔎 RX DATA sender=%s src=%s dst=%s bytes=%d",
			netutil.Uint32ToIP(senderVIP),
			netutil.Uint32ToIP(netutil.ExtractSrcIP(plaintext)),
			netutil.Uint32ToIP(dstIP),
			len(plaintext),
		)
	}
	
	// --- ENRUTAMIENTO CRÍTICO (Gateway / Site-to-Site Fix) ---

	// 1. ¿Es para MÍ (VIP)? -> Aceptamos incondicionalmente.
	if dstIP == e.localVIP {
		writeToTun(e, plaintext, plaintextBufPtr)
		return
	}

	// 2. ¿Es para OTRO peer conocido en la malla? -> Relay.
	targetPeer := e.router.Lookup(dstIP)
	if targetPeer != nil {
		if e.cfg.Debug {
			log.Printf("🔁 RELAY dst=%s via peer=%s endpoint=%v",
				netutil.Uint32ToIP(dstIP),
				netutil.Uint32ToIP(targetPeer.VirtualIP),
				targetPeer.GetEndpoint(),
			)
		}
		e.sendRelay(plaintext, plaintextBufPtr, targetPeer, peer)
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
	if e.ifce == nil {
		pool.Put(buff)
		return
	}
	packetLen := len(plaintext)
	fullPacket := buff[:TunHeadroom+packetLen]
	if _, err := e.ifce.Write([][]byte{fullPacket}, TunHeadroom); err != nil && e.cfg.Debug {
		log.Printf("❌ TUN Write Error: %v", err)
	}
	pool.Put(buff)
}

func (e *Engine) sendRelay(plaintext []byte, buff *pool.Buff, peer *PeerInfo, sourcePeer *PeerInfo) {
	endpoint := peer.GetEndpoint()

	if e.cfg.Mode == "lighthouse" && sourcePeer != nil && sourcePeer != peer {
		if sourceEndpoint := sourcePeer.GetEndpoint(); sourceEndpoint != nil && peer.ShouldNotify() {
			e.sendPeerUpdate(peer, sourcePeer.VirtualIP, sourceEndpoint)
		}
		if endpoint != nil && sourcePeer.ShouldNotify() {
			e.sendPeerUpdate(sourcePeer, peer.VirtualIP, endpoint)
		}
	}

	sessionID, aead, counter, ok := peer.NextOutbound()

	if endpoint == nil || !ok {
		pool.Put(buff)
		return
	}

	outBufPtr := pool.Get()
	outBuf := outBufPtr[:]
	
	offset := protocol.HeaderSize
	
	copy(outBuf[offset:], plaintext)
	pool.Put(buff)

	var nonceBuf [protocol.NonceSize]byte
	binary.BigEndian.PutUint64(nonceBuf[4:], counter)

	if _, err := protocol.EncodeDataHeader(outBuf[:offset], e.localVIP, sessionID, nonceBuf[:]); err != nil {
		pool.Put(outBufPtr)
		return
	}

	encrypted := aead.Seal(
		outBuf[offset:offset],
		nonceBuf[:],
		outBuf[offset:offset+len(plaintext)],
		outBuf[:offset],
	)
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
			
			peer := e.router.Lookup(dstIP)
			if peer == nil && e.cfg.Debug {
				log.Printf("❌ DROP TX: No ruta para %s", netutil.Uint32ToIP(dstIP))
			}

			if peer == nil {
				continue
			}

			endpoint := peer.GetEndpoint()
			sessionID, aead, counter, ok := peer.NextOutbound()

			if endpoint == nil || !ok {
				continue
			}

			outBufPtr := pool.Get()
			outBuf := outBufPtr[:]
			copy(outBuf[offset:], packetData)

			var nonceBuf [protocol.NonceSize]byte
			binary.BigEndian.PutUint64(nonceBuf[4:], counter)
			if _, err := protocol.EncodeDataHeader(outBuf[:offset], e.localVIP, sessionID, nonceBuf[:]); err != nil {
				pool.Put(outBufPtr)
				continue
			}

			encrypted := aead.Seal(
				outBuf[offset:offset],
				nonceBuf[:],
				outBuf[offset:offset+size],
				outBuf[:offset],
			)
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
		var batch *TxBatch
		select {
		case <-e.done:
			return nil
		case batch = <-e.txCh:
		}

		count := batch.Len
		if count == 0 {
			txBatchPool.Put(batch)
			continue
		}
		if len(e.pconns) == 0 {
			for i := 0; i < count; i++ {
				pool.Put(batch.Reqs[i].Buff)
			}
			txBatchPool.Put(batch)
			return fmt.Errorf("no UDP sockets available")
		}

		for i := 0; i < count; i++ {
			msgs[i].Buffers = [][]byte{batch.Reqs[i].Data}
			msgs[i].Addr = batch.Reqs[i].Addr
		}

		conn := e.pconns[connIdx]
		connIdx = (connIdx + 1) % len(e.pconns)
		n, err := conn.WriteBatch(msgs[:count], 0)
		if err != nil && !e.closed.Load() {
			if e.cfg.Debug {
				log.Printf("writebatch error: %v", err)
			}
		} else if err == nil && n < count && e.cfg.Debug {
			log.Printf("⚠️ WriteBatch Parcial: %d/%d enviados", n, count)
		}

		for i := 0; i < count; i++ {
			pool.Put(batch.Reqs[i].Buff)
			batch.Reqs[i] = txRequest{}
			msgs[i].Buffers = nil
			msgs[i].Addr = nil
		}
		batch.Len = 0
		txBatchPool.Put(batch)

		if err != nil {
			if e.closed.Load() {
				return nil
			}
			return err
		}
	}
}

// --- CONTROL PLANE ---

func (e *Engine) handshakeWorker() {
	for {
		select {
		case <-e.done:
			return
		case req := <-e.handshakeCh:
			e.processHandshake(req)
		}
	}
}

func (e *Engine) processHandshake(req HandshakeRequest) {
	e.processHandshakeV2(req)
}

func (e *Engine) sendHandshakeInit(p *PeerInfo) {
	e.sendHandshakeInitV2(p)
}

func (e *Engine) sendHandshakeResp(p *PeerInfo, addr *net.UDPAddr) {
}

func (e *Engine) sendHandshakePacket(p *PeerInfo, msgType uint8, addr *net.UDPAddr, cookie []byte) {
}

func (e *Engine) sendCookieReply(addr *net.UDPAddr, cookie []byte, sockIdx int) {
	pkt := pool.Get()
	defer pool.Put(pkt)

	n, _ := protocol.EncodeCookieReply(pkt[:], cookie)
	
	if sockIdx < len(e.rawConns) {
		e.rawConns[sockIdx].WriteToUDP(pkt[:n], addr)
	}
}
