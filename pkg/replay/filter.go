package replay

import (
	"sync"
)

// Constantes para la ventana deslizante.
// WindowSize 2048 bits permite una buena tolerancia a paquetes desordenados
// en enlaces de alta velocidad sin consumir mucha memoria.
const (
	WindowSize = 2048
	WordSize   = 64
	Words      = WindowSize / WordSize
)

// Filter implementa una ventana deslizante anti-replay eficiente en memoria.
// Basado en el concepto de RFC 6479 para IPsec.
type Filter struct {
	mu sync.Mutex // Protege el estado de la ventana

	lastSeq uint64          // El número de secuencia más alto visto hasta ahora
	bitmap  [Words]uint64   // Mapa de bits de paquetes vistos recientemente
}

// NewFilter crea un nuevo filtro inicializado.
func NewFilter() *Filter {
	return &Filter{}
}

// ValidateAndUpdate comprueba si el contador es válido (no es replay y no es demasiado viejo).
// Si es válido, actualiza el estado interno y devuelve true.
// Si es replay o muy viejo, devuelve false.
func (f *Filter) ValidateAndUpdate(seq uint64) bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Caso 1: Nuevo paquete con secuencia mayor a la última vista.
	if seq > f.lastSeq {
		diff := seq - f.lastSeq

		// Si el salto es mayor que la ventana entera, reiniciamos todo.
		if diff >= WindowSize {
			for i := 0; i < Words; i++ {
				f.bitmap[i] = 0
			}
			f.bitmap[0] = 1 // Marcamos el bit 0 (que corresponde al nuevo lastSeq)
			f.lastSeq = seq
			return true
		}

		// Desplazamos el bitmap (Shift lógico).
		// En lugar de mover bits (caro), calculamos índices relativos, 
		// pero para simplificar la implementación y mantener locality,
		// aquí hacemos un shift manual de palabras.
		// Nota: Para 2048 bits (32 uint64s), un shift loop es muy rápido.
		
		shiftWords := diff / WordSize
		shiftBits := diff % WordSize

		if shiftWords > 0 {
			for i := Words - 1; i >= int(shiftWords); i-- {
				f.bitmap[i] = f.bitmap[i-int(shiftWords)]
			}
			// Limpiar las palabras nuevas
			for i := 0; i < int(shiftWords); i++ {
				f.bitmap[i] = 0
			}
		}

		if shiftBits > 0 {
			carry := uint64(0)
			for i := 0; i < Words; i++ {
				newCarry := f.bitmap[i] >> (WordSize - shiftBits)
				f.bitmap[i] = (f.bitmap[i] << shiftBits) | carry
				carry = newCarry
			}
		}

		// Marcar el bit actual (siempre es el bit 0 relativo al nuevo lastSeq, 
		// pero nuestra lógica de bitmap es: bit 0 de palabra 0 es lastSeq).
		f.bitmap[0] |= 1
		f.lastSeq = seq
		return true
	}

	// Caso 2: Paquete antiguo (seq <= lastSeq)
	diff := f.lastSeq - seq

	// Si es demasiado viejo (fuera de ventana), descartar.
	if diff >= WindowSize {
		return false
	}

	// Calcular posición en el bitmap
	wordIdx := diff / WordSize
	bitIdx := diff % WordSize
	mask := uint64(1) << bitIdx

	// Verificar si ya fue visto
	if (f.bitmap[wordIdx] & mask) != 0 {
		return false // Replay detectado
	}

	// Marcar como visto
	f.bitmap[wordIdx] |= mask
	return true
}
