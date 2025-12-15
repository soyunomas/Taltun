package session

import (
	"crypto/cipher"
	"errors"
	"net"
	"sync"
	"sync/atomic" // Import añadido
	"time"
	"golang.org/x/sys/cpu"
	
	"github.com/Soyunomas/taltun/pkg/replay"
)

const cacheLineSize = 128

const (
	RekeyInterval    = 2 * time.Minute 
	KeepaliveTimeout = 10 * time.Second 
	NotifyInterval   = 5 * time.Second  
)

type Peer struct {
	// --- BLOQUE 1: Read-Mostly / Cold Data ---
	VirtualIP uint32
	
	cryptoMu  sync.RWMutex 
	aead      cipher.AEAD      
	prevAEAD  cipher.AEAD      
	
	LastHandshake    time.Time
	HandshakePending bool

	cookieMu    sync.Mutex
	LastCookie  []byte    
	CookieTime  time.Time 

	_ [cacheLineSize]byte

	// --- BLOQUE 2: Hot Control Data (Endpoint & Security) ---
	endpointMu sync.RWMutex
	endpoint   *net.UDPAddr
	
	lastSent time.Time
	lastRx   time.Time
	
	// FIX: Atomic int64 para evitar Data Race en timestamps concurrentes
	lastNotifyNano int64 

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

// ShouldNotify verifica si ha pasado suficiente tiempo de forma atómica.
func (p *Peer) ShouldNotify() bool {
	now := time.Now().UnixNano()
	last := atomic.LoadInt64(&p.lastNotifyNano)
	
	if now - last > int64(NotifyInterval) {
		// Store simple. En caso de carrera extrema, un thread podría ganar
		// y otro sobrescribir, enviando dos notificaciones. Es benigno y performante.
		atomic.StoreInt64(&p.lastNotifyNano, now)
		return true
	}
	return false
}

func (p *Peer) UpdateTimestamps(isRx bool) {
	now := time.Now()
	// Nota: lastRx/lastSent no son atómicos porque la carrera es benigna (estadística)
	// y protegerlos con mutex en cada paquete es muy costoso.
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

func (p *Peer) GetAEAD() cipher.AEAD {
	p.cryptoMu.RLock()
	defer p.cryptoMu.RUnlock()
	return p.aead
}

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

func (p *Peer) SetSessionKey(newAead cipher.AEAD) {
	p.cryptoMu.Lock()
	defer p.cryptoMu.Unlock()
	
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
