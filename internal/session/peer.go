package session

import (
	"crypto/cipher"
	"crypto/subtle"
	"errors"
	"net"
	"sync"
	"time"

	"golang.org/x/sys/cpu"

	"github.com/Soyunomas/taltun/pkg/replay"
)

// CacheLineSize se usa para evitar False Sharing.
const cacheLineSize = 128

// Constantes de Tiempos.
const (
	RekeyInterval    = 2 * time.Minute
	KeepaliveTimeout = 10 * time.Second
)

// Peer representa un nodo remoto conectado a la VPN.
type Peer struct {
	// --- BLOQUE 1: Read-Mostly / Cold Data ---
	VirtualIP uint32
	PublicKey [32]byte

	// Crypto State (Protegido por RWMutex propio)
	cryptoMu sync.RWMutex
	aead     cipher.AEAD
	prevAEAD cipher.AEAD

	LastHandshake    time.Time
	HandshakePending bool

	// Estado para DoS Protection (Cookie)
	cookieMu   sync.Mutex
	LastCookie []byte
	CookieTime time.Time

	_ [cacheLineSize]byte

	// --- BLOQUE 2: Hot Control Data (Endpoint & Security) ---
	endpointMu sync.RWMutex
	endpoint   *net.UDPAddr

	// Timestamps para Housekeeping (Keepalives).
	// TODO: migrar a atomics para eliminar la carrera bajo -race.
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

func NewPeer(vip uint32, endpoint *net.UDPAddr, publicKey [32]byte) *Peer {
	return &Peer{
		VirtualIP:    vip,
		PublicKey:    publicKey,
		endpoint:     endpoint,
		replayFilter: replay.NewFilter(),
		lastSent:     time.Now(),
		lastRx:       time.Now(),
	}
}

// MatchesPublicKey compara en tiempo constante la identidad presentada durante
// el handshake con la clave pública fijada en configuración.
func (p *Peer) MatchesPublicKey(publicKey []byte) bool {
	if len(publicKey) != len(p.PublicKey) {
		return false
	}
	return subtle.ConstantTimeCompare(p.PublicKey[:], publicKey) == 1
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
	if isRx {
		p.lastRx = now
	} else {
		p.lastSent = now
	}
}

func (p *Peer) NeedsKeepalive() bool {
	return time.Since(p.lastSent) > KeepaliveTimeout
}

func (p *Peer) NeedsRekey() bool {
	p.cryptoMu.RLock()
	defer p.cryptoMu.RUnlock()

	if p.aead == nil {
		return false
	}
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
func (p *Peer) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	p.cryptoMu.RLock()
	current := p.aead
	prev := p.prevAEAD
	p.cryptoMu.RUnlock()

	if current == nil {
		return nil, errors.New("no session key")
	}

	res, err := current.Open(dst, nonce, ciphertext, additionalData)
	if err == nil {
		return res, nil
	}

	if prev != nil {
		res, err = prev.Open(dst, nonce, ciphertext, additionalData)
		if err == nil {
			return res, nil
		}
	}

	return nil, err
}

// SetSessionKey actualiza el cifrador y rota el anterior.
//
// TODO(protocol-v2): separar TX/RX, asociar replay state a cada generación
// de clave y reiniciar contadores únicamente cuando cambie la clave.
func (p *Peer) SetSessionKey(newAEAD cipher.AEAD) {
	p.cryptoMu.Lock()
	defer p.cryptoMu.Unlock()

	if p.aead != nil {
		p.prevAEAD = p.aead
	}

	p.aead = newAEAD
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
