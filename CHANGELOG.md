# Changelog - Taltun

Todos los cambios notables en el proyecto Taltun serán documentados en este archivo.

## [v0.7.0] - TX Batching & RX Caching (Fase 7)
### 🚀 Mejoras de Rendimiento
- **TX Vectorized I/O:** Implementación de escritura por lotes (`WriteBatch/sendmmsg`) en la ruta de transmisión (TUN -> UDP).
- **Arquitectura Asíncrona:** Desacoplamiento de la lectura TUN y la escritura UDP mediante canales buffered para permitir la acumulación de paquetes sin bloquear la interfaz.
- **RX Peer Caching:** Implementación de caché de último peer visto (`Last-Peer Cache`) en el bucle de recepción para minimizar búsquedas en `map` y bloqueos `RWMutex` durante ráfagas secuenciales.

### 🛠 Sistema
- Optimización de syscalls: Reducción significativa de llamadas al sistema por paquete procesado mediante agrupación (Batch Size: 64).

---

## [v0.6.0] - RX Vectorized I/O (Fase 6)
### 🚀 Mejoras de Rendimiento
- **RX Vectorized I/O:** Implementación de lectura por lotes (`recvmmsg`) usando `ipv4.PacketConn` para leer hasta 64 paquetes por syscall.
- **Gestión de Memoria:** Adaptación de `pkg/pool` para soportar asignación de slices de punteros requerida por las lecturas vectorizadas.

### 📊 Métricas
- Validación de **Zero-Allocation** en el dataplane de recepción.
- Perfilado de CPU confirma que el tiempo de ejecución principal se ha desplazado de la gestión de memoria/runtime a las operaciones criptográficas y syscalls.

---

## [v0.5.0] - Multi-Core Scaling (Fase 5)
### ⚡ Concurrencia
- **SO_REUSEPORT:** Implementación de socket sharding en Linux. Permite múltiples descriptores de archivo en el mismo puerto UDP distribuidos por el Kernel.
- **CPU Affinity:** Distribución automática de goroutines de procesamiento (`Engine.run`) basada en `runtime.NumCPU()`.
- **Locking:** Eliminación de contención en el hot-path al aislar el estado de los sockets por hilo.

### 🛠 Infraestructura
- Scripts de benchmark automatizados (`scripts/bench_throughput.sh`) con soporte para namespaces de red.

---

## [v0.4.0] - Crypto Handshake & PFS (Fase 4)
### 🔒 Seguridad
- **ECDH Key Exchange:** Implementación de Curve25519 para negociación de claves.
- **Session Keys:** Derivación de claves de sesión únicas por peer usando `blake2s`, eliminando la PSK global para el tráfico de datos.
- **Identity:** Introducción de identificación por IP Virtual (VIP) durante el handshake.

### 🏗 Arquitectura
- **Non-Blocking Control Plane:** Separación del procesamiento de handshakes a un worker dedicado para evitar latencia en el tráfico de datos.

---

## [v0.3.0] - Routing & Multi-Client (Fase 3)
### 🚀 Features
- **Arquitectura Hub & Spoke:** Soporte para múltiples clientes simultáneos.
- **Tabla de Enrutamiento:** Implementación de `map[uint32]*Peer` para enrutamiento O(1) basado en VIP de destino.
- **NAT Traversal:** Actualización dinámica de endpoints (`IP:Port`) de clientes tras validación criptográfica exitosa.

### ⚡ Performance
- **Fast IP Conversions:** Conversión optimizada `net.IP <-> uint32` sin asignaciones.
- **Atomic Stats:** Contadores de TX/RX thread-safe usando `sync/atomic`.

---

## [v0.2.0] - Zero-Alloc Dataplane (Fase 2)
### ⚡ Performance
- **Zero-Allocation Loop:** Reescritura del bucle principal para eliminar todas las llamadas a `mallocgc` en caliente.
- **Buffer Pooling:** Integración estricta de `sync.Pool` con buffers de tamaño fijo (2048 bytes).
- **Atomic Nonces:** Generación de Nonces mediante contadores atómicos en lugar de `crypto/rand`.

---

## [v0.1.0] - Versión Inicial (Fase 1)
- Estructura básica del proyecto.
- Implementación inicial de interfaz TUN con `songgao/water`.
- Protocolo de encapsulamiento básico.
