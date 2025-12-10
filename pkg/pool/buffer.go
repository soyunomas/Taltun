package pool

import (
	"sync"
)

// BufferSize define el tamaño fijo de nuestros paquetes en memoria.
// 2048 bytes cubre holgadamente un MTU de 1500 bytes + Headers VPN.
const BufferSize = 2048

// Buff es un alias para el array fijo.
// Usamos un array en lugar de un slice para garantizar localidad de memoria
// y evitar la sobrecarga de la estructura header del slice en el pool.
type Buff [BufferSize]byte

var bPool = sync.Pool{
	New: func() interface{} {
		// Alocamos el array y devolvemos su puntero.
		// Al devolver un puntero, evitamos copiar los 2KB al sacarlo del pool.
		return new(Buff)
	},
}

// Get obtiene un buffer limpio del pool.
// El buffer devuelto tiene longitud 2048 y capacidad 2048.
// O(1) en la mayoría de casos.
func Get() *Buff {
	return bPool.Get().(*Buff)
}

// Put devuelve un buffer al pool para ser reutilizado.
// IMPORTANTE: No es necesario limpiar (zeroing) el buffer aquí si el
// consumidor (Reader) siempre sobrescribe o usa el length correcto,
// lo cual ahorra ciclos de CPU valiosos (memset es caro).
func Put(b *Buff) {
	bPool.Put(b)
}
