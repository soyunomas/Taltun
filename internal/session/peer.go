package session

import (
	"crypto/cipher"
	"crypto/subtle"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/cpu"

	tcrypto "github.com/Soyunomas/taltun/pkg/crypto"
	"github.com/Soyunomas/taltun/pkg/replay"
)

const cacheLineSize = 128

const (
	RekeyInterval        = 2 * time.Minute
	KeepaliveTimeout     = 10 * time.Second
	PreviousKeyGraceTime = 30 * time.Second
	NotifyInterval       = 5 * time.Second
	HandshakeRetryInterval = 2 * time.Second
	DirectFallbackTimeout   = 30 * time.Second
)

type trafficSession struct {
	id        uint64
	txAEAD    cipher.AEAD
	rxAEAD    cipher.AEAD
	txCounter atomic.Uint64
	replay    *replay.Filter
	createdAt time.Time
	expiresAt time.Time
}

type pendingInitiator struct {
	sessionID uint64
	ephemeral *tcrypto.KeyPair
}

type pendingResponder struct {
	sessionID          uint64
	initiatorEphemeral [tcrypto.KeySize]byte
	responderEphemeral *tcrypto.KeyPair
	keys               tcrypto.SessionKeys
}

type ipv4Prefix struct {
	network uint32
	mask    uint32
}

type Peer struct {
	VirtualIP uint32
	PublicKey [tcrypto.KeySize]byte
	allowedSources []ipv4Prefix
	lighthouse bool

	cryptoMu sync.RWMutex
	current  *trafficSession
	previous *trafficSession

	handshakeMu        sync.Mutex
	initiatorPending   *pendingInitiator
	responderPending   *pendingResponder
	LastHandshake        time.Time
	LastHandshakeAttempt time.Time
	HandshakePending     bool

	cookieMu   sync.Mutex
	LastCookie []byte
	CookieTime time.Time

	_ [cacheLineSize]byte

	endpointMu sync.RWMutex
	endpoint   *net.UDPAddr

	lastSentNano atomic.Int64
	lastRxNano   atomic.Int64
	lastNotifyNano atomic.Int64

	_ [cacheLineSize]byte

	BytesTx uint64

	_ [cacheLineSize]byte

	BytesRx uint64
}

func NewPeer(vip uint32, endpoint *net.UDPAddr, publicKey [tcrypto.KeySize]byte) *Peer {
	p := &Peer{
		VirtualIP: vip,
		PublicKey: publicKey,
		endpoint:  endpoint,
	}
	now := time.Now().UnixNano()
	p.lastSentNano.Store(now)
	p.lastRxNano.Store(now)
	return p
}

func (p *Peer) SetAllowedSources(cidrs []string) error {
	prefixes := make([]ipv4Prefix, 0, len(cidrs)+1)
	prefixes = append(prefixes, ipv4Prefix{network: p.VirtualIP, mask: ^uint32(0)})

	for _, cidr := range cidrs {
		ip, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return err
		}
		ip4 := ip.To4()
		if ip4 == nil {
			return errors.New("only IPv4 AllowedIPs are supported")
		}
		ones, bits := ipNet.Mask.Size()
		if bits != 32 || ones < 0 {
			return errors.New("invalid IPv4 AllowedIP")
		}
		network := uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
		var mask uint32
		if ones > 0 {
			mask = ^uint32(0) << (32 - ones)
		}
		prefixes = append(prefixes, ipv4Prefix{network: network & mask, mask: mask})
	}

	p.allowedSources = prefixes
	return nil
}

func (p *Peer) AllowsSource(ip uint32) bool {
	if ip == 0 {
		return false
	}
	for _, prefix := range p.allowedSources {
		if ip&prefix.mask == prefix.network {
			return true
		}
	}
	return false
}

func (p *Peer) SetLighthouse(v bool) {
	p.lighthouse = v
}

func (p *Peer) IsLighthouse() bool {
	return p.lighthouse
}

func (p *Peer) ShouldNotify() bool {
	now := time.Now().UnixNano()
	for {
		last := p.lastNotifyNano.Load()
		if last != 0 && time.Duration(now-last) < NotifyInterval {
			return false
		}
		if p.lastNotifyNano.CompareAndSwap(last, now) {
			return true
		}
	}
}

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

func (p *Peer) UpdateTimestamps(isRx bool) {
	now := time.Now().UnixNano()
	if isRx {
		p.lastRxNano.Store(now)
	} else {
		p.lastSentNano.Store(now)
	}
}

func (p *Peer) ReceiveStale(after time.Duration) bool {
	last := p.lastRxNano.Load()
	if last == 0 {
		return true
	}
	return time.Since(time.Unix(0, last)) >= after
}

func (p *Peer) NeedsKeepalive() bool {
	last := p.lastSentNano.Load()
	if last == 0 {
		return true
	}
	return time.Since(time.Unix(0, last)) > KeepaliveTimeout
}

func (p *Peer) NeedsHandshake() bool {
	if p.GetEndpoint() == nil {
		return false
	}

	p.cryptoMu.RLock()
	current := p.current
	p.cryptoMu.RUnlock()

	p.handshakeMu.Lock()
	defer p.handshakeMu.Unlock()

	now := time.Now()
	if p.HandshakePending {
		return p.LastHandshakeAttempt.IsZero() || now.Sub(p.LastHandshakeAttempt) >= HandshakeRetryInterval
	}
	if current == nil {
		return true
	}
	return now.Sub(p.LastHandshake) >= RekeyInterval
}

func (p *Peer) NeedsRekey() bool {
	p.cryptoMu.RLock()
	current := p.current
	p.cryptoMu.RUnlock()
	if current == nil {
		return false
	}

	p.handshakeMu.Lock()
	defer p.handshakeMu.Unlock()
	if p.HandshakePending {
		return false
	}
	return time.Since(p.LastHandshake) > RekeyInterval
}

func (p *Peer) BeginInitiatorHandshake(sessionID uint64, ephemeral *tcrypto.KeyPair) {
	p.handshakeMu.Lock()
	defer p.handshakeMu.Unlock()
	p.initiatorPending = &pendingInitiator{
		sessionID: sessionID,
		ephemeral: ephemeral,
	}
	p.LastHandshakeAttempt = time.Now()
	p.HandshakePending = true
}

func (p *Peer) PendingInitiatorSessionID() uint64 {
	p.handshakeMu.Lock()
	defer p.handshakeMu.Unlock()
	if p.initiatorPending == nil {
		return 0
	}
	return p.initiatorPending.sessionID
}

func (p *Peer) GetInitiatorHandshake(sessionID uint64) (*tcrypto.KeyPair, bool) {
	p.handshakeMu.Lock()
	defer p.handshakeMu.Unlock()
	if p.initiatorPending == nil || p.initiatorPending.sessionID != sessionID {
		return nil, false
	}
	return p.initiatorPending.ephemeral, true
}

func (p *Peer) SetResponderHandshake(
	sessionID uint64,
	initiatorEphemeral [tcrypto.KeySize]byte,
	responderEphemeral *tcrypto.KeyPair,
	keys tcrypto.SessionKeys,
) {
	p.handshakeMu.Lock()
	defer p.handshakeMu.Unlock()
	p.responderPending = &pendingResponder{
		sessionID:          sessionID,
		initiatorEphemeral: initiatorEphemeral,
		responderEphemeral: responderEphemeral,
		keys:               keys,
	}
}

func (p *Peer) GetResponderHandshake(sessionID uint64) (
	initiatorEphemeral [tcrypto.KeySize]byte,
	responderEphemeral *tcrypto.KeyPair,
	keys tcrypto.SessionKeys,
	ok bool,
) {
	p.handshakeMu.Lock()
	defer p.handshakeMu.Unlock()
	if p.responderPending == nil || p.responderPending.sessionID != sessionID {
		return initiatorEphemeral, nil, keys, false
	}
	return p.responderPending.initiatorEphemeral, p.responderPending.responderEphemeral, p.responderPending.keys, true
}

func (p *Peer) CompleteInitiatorHandshake(sessionID uint64, txKey, rxKey [tcrypto.KeySize]byte) error {
	p.handshakeMu.Lock()
	defer p.handshakeMu.Unlock()

	if p.initiatorPending == nil || p.initiatorPending.sessionID != sessionID {
		return errors.New("no matching initiator handshake")
	}
	if err := p.installSession(sessionID, txKey, rxKey); err != nil {
		return err
	}
	p.initiatorPending = nil
	p.HandshakePending = false
	p.LastHandshakeAttempt = time.Time{}
	p.LastHandshake = time.Now()
	return nil
}

func (p *Peer) CompleteResponderHandshake(sessionID uint64) error {
	p.handshakeMu.Lock()
	defer p.handshakeMu.Unlock()

	if p.responderPending == nil || p.responderPending.sessionID != sessionID {
		return errors.New("no matching responder handshake")
	}
	if err := p.installSession(
		sessionID,
		p.responderPending.keys.ResponderToInitiator,
		p.responderPending.keys.InitiatorToResponder,
	); err != nil {
		return err
	}
	p.responderPending = nil
	p.HandshakePending = false
	p.LastHandshakeAttempt = time.Time{}
	p.LastHandshake = time.Now()
	return nil
}

func (p *Peer) AbortHandshake(sessionID uint64) {
	p.handshakeMu.Lock()
	defer p.handshakeMu.Unlock()
	if p.initiatorPending != nil && p.initiatorPending.sessionID == sessionID {
		p.initiatorPending = nil
	}
	if p.responderPending != nil && p.responderPending.sessionID == sessionID {
		p.responderPending = nil
	}
	if p.initiatorPending == nil && p.responderPending == nil {
		p.HandshakePending = false
		p.LastHandshakeAttempt = time.Time{}
	}
}

func (p *Peer) installSession(sessionID uint64, txKey, rxKey [tcrypto.KeySize]byte) error {
	txAEAD, err := tcrypto.NewAEAD(txKey)
	if err != nil {
		return err
	}
	rxAEAD, err := tcrypto.NewAEAD(rxKey)
	if err != nil {
		return err
	}

	now := time.Now()
	next := &trafficSession{
		id:        sessionID,
		txAEAD:    txAEAD,
		rxAEAD:    rxAEAD,
		replay:    replay.NewFilter(),
		createdAt: now,
	}

	p.cryptoMu.Lock()
	defer p.cryptoMu.Unlock()
	if p.current != nil {
		p.current.expiresAt = now.Add(PreviousKeyGraceTime)
		p.previous = p.current
	}
	p.current = next
	p.prunePreviousLocked(now)
	return nil
}

func (p *Peer) NextOutbound() (sessionID uint64, aead cipher.AEAD, counter uint64, ok bool) {
	p.cryptoMu.RLock()
	current := p.current
	p.cryptoMu.RUnlock()
	if current == nil {
		return 0, nil, 0, false
	}

	for {
		old := current.txCounter.Load()
		if old == ^uint64(0) {
			return 0, nil, 0, false
		}
		if current.txCounter.CompareAndSwap(old, old+1) {
			return current.id, current.txAEAD, old + 1, true
		}
	}
}

func (p *Peer) Open(
	sessionID uint64,
	dst, nonce, ciphertext, additionalData []byte,
	counter uint64,
) ([]byte, error) {
	p.cryptoMu.Lock()
	now := time.Now()
	p.prunePreviousLocked(now)

	var candidate *trafficSession
	switch {
	case p.current != nil && p.current.id == sessionID:
		candidate = p.current
	case p.previous != nil && p.previous.id == sessionID:
		candidate = p.previous
	default:
		p.cryptoMu.Unlock()
		return nil, errors.New("unknown or expired session")
	}
	p.cryptoMu.Unlock()

	plaintext, err := candidate.rxAEAD.Open(dst, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, err
	}
	if !candidate.replay.ValidateAndUpdate(counter) {
		return nil, errors.New("replayed packet")
	}
	return plaintext, nil
}

func (p *Peer) CurrentSessionID() uint64 {
	p.cryptoMu.RLock()
	defer p.cryptoMu.RUnlock()
	if p.current == nil {
		return 0
	}
	return p.current.id
}

func (p *Peer) SessionIDInUse(sessionID uint64) bool {
	if sessionID == 0 {
		return true
	}

	p.cryptoMu.Lock()
	defer p.cryptoMu.Unlock()
	p.prunePreviousLocked(time.Now())

	if p.current != nil && p.current.id == sessionID {
		return true
	}
	return p.previous != nil && p.previous.id == sessionID
}

func (p *Peer) PreviousSessionID() uint64 {
	p.cryptoMu.Lock()
	defer p.cryptoMu.Unlock()
	p.prunePreviousLocked(time.Now())
	if p.previous == nil {
		return 0
	}
	return p.previous.id
}

func (p *Peer) prunePreviousLocked(now time.Time) {
	if p.previous != nil && !p.previous.expiresAt.IsZero() && !now.Before(p.previous.expiresAt) {
		p.previous = nil
	}
}

func (p *Peer) ExpirePreviousForTest() {
	p.cryptoMu.Lock()
	defer p.cryptoMu.Unlock()
	if p.previous != nil {
		p.previous.expiresAt = time.Now().Add(-time.Second)
	}
	p.prunePreviousLocked(time.Now())
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
	return append([]byte(nil), p.LastCookie...)
}

var _ = cpu.CacheLinePad{}
