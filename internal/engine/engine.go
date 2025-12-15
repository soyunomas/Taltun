package engine

import (
	"context"
	"fmt"
	"log"
	"net"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/Soyunomas/taltun/internal/config"
	"github.com/Soyunomas/taltun/internal/session"
	"github.com/Soyunomas/taltun/pkg/cookie"
	"github.com/Soyunomas/taltun/pkg/crypto"
	"github.com/Soyunomas/taltun/pkg/netutil"
	"github.com/Soyunomas/taltun/pkg/router"
	
	"golang.org/x/net/ipv4"
	"golang.zx2c4.com/wireguard/tun"
)

type Engine struct {
	cfg   *config.Config
	
	ifce  tun.Device
	
	pconns []*ipv4.PacketConn
	rawConns []*net.UDPConn
	
	staticKey *crypto.KeyPair
	localVIP  uint32

	cookieProtector *cookie.Protector

	peers        atomic.Pointer[PeerMap]
	router       *router.Router 
	peersWriteMu sync.Mutex

	handshakeCh chan HandshakeRequest
	txCh        chan *TxBatch
	
	txCounter   uint64
	closed atomic.Bool
}

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

	if udpAddr != nil {
		e.router.Insert(fmt.Sprintf("%s/32", virtualIP.String()), p)
	} else {
		log.Printf("⏳ Peer %s añadido sin endpoint (Esperando descubrimiento)", virtualIP)
	}

	for _, cidr := range allowedIPs {
		if err := e.router.Insert(cidr, p); err != nil {
			log.Printf("⚠️ Error añadiendo AllowedIP %s para peer %s: %v", cidr, virtualIP, err)
		} else {
			log.Printf("twisted_rightwards_arrows Route: %s -> Peer %s", cidr, virtualIP)
		}
	}

	return nil
}

func (e *Engine) PromotePeerRoute(p *session.Peer) {
	vip := netutil.Uint32ToIP(p.VirtualIP)
	cidr := fmt.Sprintf("%s/32", vip.String())
	e.router.Insert(cidr, p)
	if e.cfg.Debug {
		log.Printf("🚀 Ruta Directa Promocionada: %s -> %s", cidr, p.GetEndpoint())
	}
}

func (e *Engine) Initialize() error {
	// OPTIMIZACIÓN LIGHTHOUSE:
	// Si somos Lighthouse puro, no necesitamos interfaz TUN ni IPs del sistema.
	// Solo sockets UDP.
	if e.cfg.Mode != "lighthouse" {
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
	} else {
		log.Println("💡 Iniciando en modo LIGHTHOUSE (Sin interfaz TUN)")
	}

	numCPU := runtime.NumCPU()
	e.pconns = make([]*ipv4.PacketConn, numCPU)
	e.rawConns = make([]*net.UDPConn, numCPU)
	
	log.Printf("⚙️ Inicializando %d sockets Batch UDP...", numCPU)

	for i := 0; i < numCPU; i++ {
		c, err := netutil.ListenUDPReusePort("udp", e.cfg.LocalAddr)
		if err != nil {
			if e.ifce != nil { e.ifce.Close() }
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
	log.Println("🛑 Cerrando recursos...")
	
	for _, c := range e.rawConns {
		c.Close()
	}
	
	if e.ifce != nil {
		e.ifce.Close()
	}
}

func (e *Engine) Run(ctx context.Context) error {
	// Si es lighthouse, solo necesitamos workers que procesen UDP -> Lógica
	// No necesitamos TunRead (porque no hay TUN) ni TunWrite (porque no hay TUN).
	
	numWorkers := len(e.pconns)
	// Canales de error + workers extra
	errChan := make(chan error, numWorkers + 5)

	// 1. RX Workers (UDP Input)
	for i, pc := range e.pconns {
		idx := i
		pconn := pc
		go func() {
			errChan <- e.loopUdpBatchToTun(pconn, idx)
		}()
	}

	// 2. TX Worker (UDP Output)
	go func() { errChan <- e.loopUdpBatchWrite() }()
	
	// 3. Control Plane
	go func() { errChan <- e.housekeepingWorker(ctx) }() 
	go e.handshakeWorker()

	// 4. TUN Reader (Solo si NO es Lighthouse)
	if e.cfg.Mode != "lighthouse" {
		go func() { errChan <- e.loopTunReadAndEncrypt() }()
	}

	log.Printf("🚀 Engine Running (%s): %d Cores | VIP: %s", 
		e.cfg.Mode, numWorkers, e.cfg.LocalVIP)
	
	// Handshake inicial solo si somos cliente/server normal
	if e.cfg.Mode != "lighthouse" {
		currentPeers := *e.peers.Load()
		for _, p := range currentPeers {
			if p.GetEndpoint() != nil {
				go e.sendHandshakeInit(p)
			}
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
