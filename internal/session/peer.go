package session

import (
	"crypto/cipher"
	"net"
	"sync"
	"time"
)

// Peer representa un nodo remoto conectado a la VPN.
type Peer struct {
	// -- Datos de acceso frecuente (Hot Path) --
	// Protegidos por RWMutex separados para minimizar contención.
	
	endpoint   *net.UDPAddr
	endpointMu sync.RWMutex

	// Crypto State
	// Si aead es nil, el handshake no se ha completado.
	aead      cipher.AEAD
	cryptoMu  sync.RWMutex 

	// ID de sesión (VIP)
	VirtualIP uint32

	// Handshake State
	LastHandshake time.Time
	HandshakePending bool

	// -- Estadísticas (Atomic) --
	BytesTx uint64
	BytesRx uint64
}

func NewPeer(vip uint32, endpoint *net.UDPAddr) *Peer {
	return &Peer{
		VirtualIP: vip,
		endpoint:  endpoint,
	}
}

// GetEndpoint retorna la dirección UDP actual.
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

// GetAEAD devuelve el cifrador actual del peer de forma thread-safe.
func (p *Peer) GetAEAD() cipher.AEAD {
	p.cryptoMu.RLock()
	defer p.cryptoMu.RUnlock()
	return p.aead
}

// SetSessionKey actualiza el cifrador tras un handshake exitoso.
func (p *Peer) SetSessionKey(aead cipher.AEAD) {
	p.cryptoMu.Lock()
	defer p.cryptoMu.Unlock()
	p.aead = aead
	p.LastHandshake = time.Now()
	p.HandshakePending = false
}
