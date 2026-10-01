package router

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"github.com/Soyunomas/taltun/internal/session"
	"github.com/Soyunomas/taltun/pkg/netutil"
)

type trieNode struct {
	children [2]*trieNode
	peer     *session.Peer
}

// Router implements exact IPv4 longest-prefix match.
//
// Readers are lock-free. Writers serialize, clone only the path being changed,
// and publish a new immutable root atomically. Nodes reachable from a published
// root are never mutated.
type Router struct {
	root atomic.Pointer[trieNode]
	mu   sync.Mutex
}

func New() *Router {
	r := &Router{}
	r.root.Store(&trieNode{})
	return r
}

func (r *Router) Insert(cidr string, p *session.Peer) error {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	if ip.To4() == nil {
		return fmt.Errorf("only IPv4 routes are supported: %s", cidr)
	}

	ones, bits := ipNet.Mask.Size()
	if bits != 32 || ones < 0 || ones > 32 {
		return fmt.Errorf("invalid IPv4 prefix: %s", cidr)
	}
	network := netutil.IPToUint32(ipNet.IP)

	r.mu.Lock()
	defer r.mu.Unlock()

	oldRoot := r.root.Load()
	if oldRoot == nil {
		oldRoot = &trieNode{}
	}
	newRoot := clonePath(oldRoot, network, 0, ones, p)
	r.root.Store(newRoot)
	return nil
}

func clonePath(old *trieNode, ip uint32, depth, prefixLen int, p *session.Peer) *trieNode {
	next := &trieNode{}
	if old != nil {
		*next = *old
	}

	if depth == prefixLen {
		next.peer = p
		return next
	}

	bit := int((ip >> (31 - depth)) & 1)
	var oldChild *trieNode
	if old != nil {
		oldChild = old.children[bit]
	}
	next.children[bit] = clonePath(oldChild, ip, depth+1, prefixLen, p)
	return next
}

func (r *Router) Lookup(ip uint32) *session.Peer {
	node := r.root.Load()
	var best *session.Peer

	for depth := 0; node != nil && depth <= 32; depth++ {
		if node.peer != nil {
			best = node.peer
		}
		if depth == 32 {
			break
		}
		bit := int((ip >> (31 - depth)) & 1)
		node = node.children[bit]
	}
	return best
}
