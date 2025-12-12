package session

import (
	"crypto/cipher"
	"errors"
	"net"
	"sync"
	"time"
	"golang.org/x/sys/cpu"
	
	"github.com/Soyunomas/taltun/pkg/replay"
)

// CacheLineSize se usa para evitar False Sharing.
const cacheLineSize = 128

// Constantes de Tiempos
const (
	RekeyInterval    = 2 * time.Minute // Rotar claves cada 2 min
	KeepaliveTimeout = 10 * time.Second // Enviar ping si hay silencio 10s
)

// Peer representa un nodo remoto conectado a la VPN.
type Peer struct {
	// --- BLOQUE 1: Read-Mostly / Cold Data ---
	VirtualIP uint32
	
	// Crypto State (Protegido por RWMutex propio)
	cryptoMu  sync.RWMutex 
	aead      cipher.AEAD      // Clave actual
	prevAEAD  cipher.AEAD      // Clave anterior (para transición suave)
	
	LastHandshake    time.Time
	HandshakePending bool

	// Estado para DoS Protection (Cookie)
	cookieMu    sync.Mutex
	LastCookie  []byte    
	CookieTime  time.Time 

	_ [cacheLineSize]byte

	// --- BLOQUE 2: Hot Control Data (Endpoint & Security) ---
	endpointMu sync.RWMutex
	endpoint   *net.UDPAddr
	
	// Timestamps para Housekeeping (Keepalives)
	// Se acceden frecuentemente, los protegemos o usamos atomics si fuera necesario estricto.
	// Por simplicidad en esta fase, usaremos el endpointMu o acceso directo relajado (son tiempos).
	lastSent time.Time
	lastRx   time.Time

	// Anti-Replay Filter
	replayFilter *replay.Filter

	_ [cacheLineSize]byte

	// --- BLOQUE 3: Atomic Counters (Hot Writes) ---
	BytesTx uint64
	
	_ [cacheLineSize]byte

	BytesRx uint64
}

func NewPeer(vip uint32, endpoint *net.UDPAddr) *Peer {
	return &Peer{
		VirtualIP:    vip,
		endpoint:     endpoint,
		replayFilter: replay.NewFilter(),
		lastSent:     time.Now(),
		lastRx:       time.Now(),
	}
}

func (p *Peer) GetEndpoint() *net.UDPAddr {
	p.endpointMu.RLock()
	defer p.endpointMu.RUnlock()
	return p.endpoint
}

func (p *Peer) SetEndpoint(addr *net.UDPAddr) {
	p.endpointMu.Lock()
	defer p.endpointMu.Unlock()
	p.endpoint = addr
}

// UpdateTimestamps actualiza los contadores de actividad.
// isRx=true (Recibido), isRx=false (Enviado)
func (p *Peer) UpdateTimestamps(isRx bool) {
	now := time.Now()
	// No usamos lock aquí para no frenar el dataplane.
	// La carrera de datos en un time.Time es benigna para keepalives.
	if isRx {
		p.lastRx = now
	} else {
		p.lastSent = now
	}
}

func (p *Peer) NeedsKeepalive() bool {
	// Si hemos enviado algo hace poco, no hace falta keepalive.
	return time.Since(p.lastSent) > KeepaliveTimeout
}

func (p *Peer) NeedsRekey() bool {
	p.cryptoMu.RLock()
	defer p.cryptoMu.RUnlock()
	
	// Si no tenemos clave, no hacemos rekey (necesitamos handshake inicial).
	if p.aead == nil {
		return false
	}
	
	// Si ya estamos negociando, esperar.
	if p.HandshakePending {
		return false
	}
	
	return time.Since(p.LastHandshake) > RekeyInterval
}

func (p *Peer) MarkHandshakePending() {
	p.cryptoMu.Lock()
	p.HandshakePending = true
	p.cryptoMu.Unlock()
}

// GetAEAD devuelve el cifrador actual.
func (p *Peer) GetAEAD() cipher.AEAD {
	p.cryptoMu.RLock()
	defer p.cryptoMu.RUnlock()
	return p.aead
}

// Open intenta descifrar usando la clave actual, y si falla, la anterior.
// Esto permite rotación de claves sin pérdida de paquetes (Graceful Rotation).
func (p *Peer) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	p.cryptoMu.RLock()
	current := p.aead
	prev := p.prevAEAD
	p.cryptoMu.RUnlock()

	if current == nil {
		return nil, errors.New("no session key")
	}

	// 1. Intentar clave actual (Happy Path)
	res, err := current.Open(dst, nonce, ciphertext, additionalData)
	if err == nil {
		return res, nil
	}

	// 2. Intentar clave anterior (Transition Path)
	// Solo si existe y el error fue de autenticación (no de tamaño, etc)
	if prev != nil {
		res, err = prev.Open(dst, nonce, ciphertext, additionalData)
		if err == nil {
			return res, nil
		}
	}

	return nil, err
}

// SetSessionKey actualiza el cifrador y rota el anterior.
func (p *Peer) SetSessionKey(newAead cipher.AEAD) {
	p.cryptoMu.Lock()
	defer p.cryptoMu.Unlock()
	
	// Rotación: La actual pasa a ser la previa.
	if p.aead != nil {
		p.prevAEAD = p.aead
	}
	
	p.aead = newAead
	p.LastHandshake = time.Now()
	p.HandshakePending = false
}

func (p *Peer) ValidateReplay(counter uint64) bool {
	return p.replayFilter.ValidateAndUpdate(counter)
}

func (p *Peer) SetCookie(cookie []byte) {
	p.cookieMu.Lock()
	defer p.cookieMu.Unlock()
	c := make([]byte, len(cookie))
	copy(c, cookie)
	p.LastCookie = c
	p.CookieTime = time.Now()
}

func (p *Peer) GetCookie() []byte {
	p.cookieMu.Lock()
	defer p.cookieMu.Unlock()
	
	if len(p.LastCookie) == 0 {
		return nil
	}
	if time.Since(p.CookieTime) > 5*time.Minute {
		p.LastCookie = nil
		return nil
	}
	return p.LastCookie
}

var _ = cpu.CacheLinePad{}
