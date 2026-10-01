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
	CookieSize = 16
)

type Protector struct {
	mu sync.RWMutex

	currentSecret [SecretSize]byte
	prevSecret    [SecretSize]byte
	lastRotate    time.Time

	done      chan struct{}
	closeOnce sync.Once
}

func NewProtector() *Protector {
	p := &Protector{done: make(chan struct{})}
	p.rotateSecrets()
	go p.rotationLoop()
	return p
}

func (p *Protector) Close() {
	if p == nil {
		return
	}
	p.closeOnce.Do(func() {
		close(p.done)
	})
}

func (p *Protector) GenerateCookie(ip net.IP) []byte {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.mac(ip, p.currentSecret[:])
}

func (p *Protector) ValidateCookie(ip net.IP, cookie []byte) bool {
	if len(cookie) != CookieSize {
		return false
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	expected := p.mac(ip, p.currentSecret[:])
	if hmac.Equal(cookie, expected) {
		return true
	}
	expectedPrev := p.mac(ip, p.prevSecret[:])
	return hmac.Equal(cookie, expectedPrev)
}

func (p *Protector) mac(ip net.IP, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(ip)
	sum := mac.Sum(nil)
	return append([]byte(nil), sum[:CookieSize]...)
}

func (p *Protector) rotationLoop() {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.rotateSecrets()
		case <-p.done:
			return
		}
	}
}

func (p *Protector) rotateSecrets() {
	var next [SecretSize]byte
	if _, err := rand.Read(next[:]); err != nil {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.prevSecret = p.currentSecret
	p.currentSecret = next
	p.lastRotate = time.Now()
}
