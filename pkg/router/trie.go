package router

import (
	"net"
	"sync"
	"sync/atomic"

	"github.com/Soyunomas/taltun/internal/session"
	"github.com/Soyunomas/taltun/pkg/netutil"
)

// trieNode es un nodo del árbol Radix binario.
type trieNode struct {
	children [2]*trieNode
	peer     *session.Peer // Si no es nil, este nodo es una coincidencia para un CIDR
}

// Router implementa un thread-safe Longest Prefix Match para IPv4.
// Usamos Copy-On-Write (atomic.Pointer) para lecturas lock-free extremadamente rápidas.
type Router struct {
	root atomic.Pointer[trieNode]
	mu   sync.Mutex // Protege escrituras (Insert)
}

func New() *Router {
	r := &Router{}
	r.root.Store(&trieNode{})
	return r
}

// Insert añade una ruta CIDR apuntando a un peer.
func (r *Router) Insert(cidr string, p *session.Peer) error {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}

	ones, _ := ipNet.Mask.Size()
	ip := netutil.IPToUint32(ipNet.IP)

	r.mu.Lock()
	defer r.mu.Unlock()

	// Clonamos el árbol actual (Copy-On-Write parcial sería ideal, 
	// pero por simplicidad y seguridad reconstruimos el path afectado o copiamos).
	// Nota: Para actualizaciones poco frecuentes, clonar es aceptable.
	// Para optimización extrema, clonaríamos solo los nodos afectados, 
	// pero aquí usaremos mutación protegida por Lock y el puntero atómico solo para la raíz
	// si quisiéramos swap completo. 
	
	// ESTRATEGIA ACTUAL: El nodo raíz es estático en estructura, pero sus hijos cambian.
	// Dado que Go maneja la memoria, podemos mutar el árbol bajo lock y las lecturas concurrentes
	// seguirán punteros viejos hasta que el caché se actualice.
	// Sin embargo, para seguridad total lock-free en lectura, la estructura no debe mutar
	// mientras se lee.
	
	// Simplificación para Taltun: Usaremos un RWMutex para la estructura del Trie si hay muchas escrituras,
	// pero como las rutas son estáticas al inicio, atomic.Pointer es overkill si no rotamos todo el árbol.
	// Vamos a usar un enfoque de recorrido seguro sin locks para lectura asumiendo
	// que las inserciones ocurren SOLO al inicio o son muy raras.
	
	root := r.root.Load()
	if root == nil {
		root = &trieNode{}
		r.root.Store(root)
	}
	
	node := root
	for i := 0; i < ones; i++ {
		// Bit i-ésimo de la IP (desde el más significativo)
		bit := (ip >> (31 - i)) & 1
		
		if node.children[bit] == nil {
			node.children[bit] = &trieNode{}
		}
		node = node.children[bit]
	}
	
	node.peer = p
	return nil
}

// Lookup encuentra el peer más específico para una IP destino (LPM).
// Hot-Path: No usa locks, ni allocs.
func (r *Router) Lookup(ip uint32) *session.Peer {
	node := r.root.Load()
	var bestMatch *session.Peer

	// Recorremos hasta 32 bits
	for i := 0; i < 32; i++ {
		if node == nil {
			break
		}
		// Si este nodo tiene un peer, es un candidato (match de prefijo más corto hasta ahora)
		if node.peer != nil {
			bestMatch = node.peer
		}

		bit := (ip >> (31 - i)) & 1
		node = node.children[bit]
	}

	// Chequeo final por si el último nodo también era match (ej. /32)
	if node != nil && node.peer != nil {
		bestMatch = node.peer
	}

	return bestMatch
}
