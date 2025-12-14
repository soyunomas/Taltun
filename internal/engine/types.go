package engine

import (
	"net"
	"sync"

	"github.com/Soyunomas/taltun/internal/session"
	"github.com/Soyunomas/taltun/pkg/pool"
)

// BatchSize define cuántos paquetes leemos/escribimos de golpe.
const BatchSize = 64

// TunHeadroom: Espacio reservado al inicio del buffer para que el driver TUN
// escriba sus cabeceras (Packet Info) sin realocar memoria.
const TunHeadroom = 16

// Alias para facilitar lectura
type PeerMap = map[uint32]*PeerInfo
type PeerInfo = session.Peer

type HandshakeRequest struct {
	RemoteAddr *net.UDPAddr
	Packet     []byte
	ConnIndex  int
}

// txRequest representa un paquete ya encriptado listo para enviar.
type txRequest struct {
	Data []byte       // Slice sobre el buffer del pool
	Buff *pool.Buff   // Puntero original para devolverlo al pool
	Addr *net.UDPAddr // Destino
}

type TxBatch struct {
	Reqs [BatchSize]txRequest
	Len  int
}

// Pool compartido para los lotes de transmisión
var txBatchPool = sync.Pool{
	New: func() interface{} {
		return &TxBatch{}
	},
}
