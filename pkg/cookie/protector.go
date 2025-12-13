package cookie

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"net"
	"sync"
	"time"
)

const (
	SecretSize = 32
	CookieSize = 16 // Truncamos SHA256 a 128 bits para ahorrar ancho de banda
)

// Protector gestiona la generación y validación de cookies stateless.
// Utiliza rotación de claves para invalidar cookies viejas automáticamente.
type Protector struct {
	mu sync.RWMutex
	
	currentSecret [SecretSize]byte
	prevSecret    [SecretSize]byte
	
	lastRotate time.Time
}

func NewProtector() *Protector {
	p := &Protector{}
	p.rotateSecrets() // Inicializar claves
	
	// Iniciar rotación automática
	go p.rotationLoop()
	
	return p
}

// GenerateCookie crea un HMAC basado en la IP origen y el secreto actual.
// Stateless: El servidor no guarda nada.
func (p *Protector) GenerateCookie(ip net.IP) []byte {
	p.mu.RLock()
	defer p.mu.RUnlock()
	
	return p.mac(ip, p.currentSecret[:])
}

// ValidateCookie verifica si la cookie es válida para la IP dada.
// Comprueba tanto la clave actual como la anterior (para tolerar la rotación).
func (p *Protector) ValidateCookie(ip net.IP, cookie []byte) bool {
	if len(cookie) != CookieSize {
		return false
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	// 1. Probar con secreto actual
	expected := p.mac(ip, p.currentSecret[:])
	if hmac.Equal(cookie, expected) {
		return true
	}

	// 2. Probar con secreto anterior (grace period)
	expectedPrev := p.mac(ip, p.prevSecret[:])
	if hmac.Equal(cookie, expectedPrev) {
		return true
	}

	return false
}

func (p *Protector) mac(ip net.IP, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(ip) // IP debería ser IPv4 (4 bytes) o IPv6 (16 bytes) canonicalizada
	sum := mac.Sum(nil)
	return sum[:CookieSize]
}

func (p *Protector) rotationLoop() {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()
	
	for range ticker.C {
		p.rotateSecrets()
	}
}

func (p *Protector) rotateSecrets() {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	// Mover actual -> previo
	p.prevSecret = p.currentSecret
	
	// Generar nuevo actual
	if _, err := rand.Read(p.currentSecret[:]); err != nil {
		// Fallback crítico si falla RNG (no debería pasar)
		// Simplemente no rotamos para no dejar el sistema inusable con ceros.
		return 
	}
	p.lastRotate = time.Now()
}
