# Changelog - Taltun

Todos los cambios notables en el proyecto Taltun serán documentados en este archivo.

> Las entradas antiguas reflejan el estado y las afirmaciones de cada versión en su momento. Para garantías actuales y resultados reproducibles, usa `docs/SECURITY.md` y `docs/PERFORMANCE.md`.

## [v0.11.0-rc1] - Security & Reliability Hardening

### Seguridad
- Identidad X25519 fijada por peer y prueba de posesión de la clave privada.
- Handshake v2 con X25519 efímero, transcript autenticado, `session_id` aleatorio y confirmación final.
- HKDF-SHA256 para claves de tráfico direccionales y clave de confirmación.
- Contadores y ventanas anti-replay por generación de sesión, con transición de 30 segundos para la generación anterior.
- Cabeceras de datos y control autenticadas como AAD de ChaCha20-Poly1305.
- `AllowedIPs` aplicado también como ACL de origen.
- `PeerUpdate` de Lighthouse cifrado, autenticado, rate-limited y protegido frente a replay.

### Routing y concurrencia
- Trie IPv4 LPM exacto con copy-on-write real y publicación atómica.
- Promoción de rutas directas sólo tras endpoint autenticado.
- Timestamps calientes y rate-limit de Lighthouse atómicos.
- Shutdown idempotente, workers coordinados con WaitGroup y rotación de cookies detenible.
- Validación de MTU 576..2007 y número configurable de workers UDP.

### Verificación
- CI: vet, unit tests, race detector, fuzzing de parsers y build.
- Integración privilegiada con namespaces: relay cliente-cliente, subnet routing, restart y rekey automático.
- Workflow Performance con pprof, iperf3, latencia, pérdida y microbenchmarks de allocations.

### Rendimiento de referencia
En el run de GitHub Actions Performance `36919598224` (Azure 4 vCPU, MTU 1380):
- 1 worker: ~0,889 Gbit/s TCP.
- 4 workers: ~1,126 Gbit/s TCP.
- Pérdida UDP a 1 Gbit/s ofrecido: ~27,7% con 1 worker y ~9,0% con 4.
- Parser/encoder de cabecera: 0 allocs/op.
- Session seal/open: 1 alloc/op en el microbenchmark medido.

Estas cifras son específicas de ese entorno y no constituyen una garantía universal.

### Compatibilidad
- Protocolo v2 no es wire-compatible con v0.10 y anteriores.
- `public_key` es obligatorio por peer.
- `lighthouse = true` declara explícitamente un peer de descubrimiento confiable.
- IPv4 únicamente en esta release candidate.

---

## [v0.10.0] - Internal Switching & Relay (Fase 10)
### 🔀 Advanced Routing (Routing V2)
- **Radix Trie (LPM):** Reemplazo del mapa plano `map[uint32]*Peer` por una estructura de datos de árbol (`Radix Tree`) optimizada para IPv4. Permite búsquedas de prefijos CIDR (Longest Prefix Match), habilitando arquitecturas **Site-to-Site** donde un peer da acceso a toda una subred (ej. `192.168.1.0/24`).
- **User-Space Relay (Hairpinning):** Implementación de lógica de conmutación interna. Si un paquete recibido por el servidor tiene como destino otro peer conectado, Taltun lo re-encripta y reenvía directamente en el espacio de usuario.
    - Evita el coste de cambios de contexto (TUN Write -> Kernel Routing -> TUN Read).
    - Permite comunicación **Client-to-Client** sin necesidad de configurar `ip forwarding` o `iptables` en el host.
- **AllowedIPs:** Nueva directiva de configuración para definir qué rangos de IP (CIDRs) se permiten y enrutan a través de cada peer.

---

## [v0.9.1] - Security Hardening (Fase 9)
### 🛡️ Seguridad y Resiliencia
- **Anti-Replay Protection:** Implementación de ventana deslizante de 2048 bits (RFC 6479) para rechazar paquetes duplicados o reinyectados con coste O(1).
- **DoS Protection (Stateless Cookies):** Mecanismo de defensa contra inundación de Handshakes. Bajo carga, el servidor exige a los clientes una prueba criptográfica (Cookie HMAC) vinculada a su IP antes de realizar operaciones costosas (Curve25519).
- **Graceful Rekeying:** Rotación automática de claves de sesión cada 2 minutos para garantizar *Perfect Forward Secrecy* (PFS). Soporte para descifrado transicional (Current/Prev Key) para evitar pérdida de paquetes durante el cambio.

### 💓 Conectividad
- **Keepalives:** Envío automático de `Heartbeats` (paquetes vacíos cifrados) cada 10 segundos de inactividad para mantener abiertas las tablas NAT/Firewalls intermedios.
- **Dead Peer Detection:** Actualización de timestamps de última actividad (RX/TX) para gestión de estado de conexión.

---

## [v0.9.0] - Modern TUN & GSO (Fase 9)
### 🚀 Core Engine
- **WireGuard TUN:** Reemplazo de `songgao/water` por la implementación estándar industrial `wireguard-go/tun`. Habilita soporte nativo para **GSO (Generic Segmentation Offload)** y **GRO**, permitiendo al Kernel entregar "super-paquetes" de hasta 64KB reduciendo la sobrecarga de interrupciones.
- **TUN Vectorized I/O:** Implementación de lectura por lotes desde la interfaz virtual (`tun.ReadBatch`). El motor ahora lee múltiples paquetes IP del Kernel en una sola llamada al sistema, alineándose con la optimización de UDP `recvmmsg` ya existente.
- **Headroom para cabecera:** uso de offset reads para reservar espacio antes del payload. La implementación actual todavía copia payload hacia buffers de salida en TX/relay; no se considera zero-copy end-to-end.

### ⚡ Concurrency & Latency (Engineering Refinements)
- **Lock-Free Dataplane:** Eliminación de `sync.RWMutex` en el path crítico de lectura (RX/TX) mediante el patrón **Copy-On-Write** con `atomic.Pointer`. Elimina la contención de bloqueos en cargas de trabajo multicore.
- **Memory Layout Optimization:** Reestructuración del objeto `Peer` con **Memory Padding** (128 bytes) para aislar contadores atómicos y evitar *False Sharing* (Cache Line bouncing) entre hilos.
- **Batch Channeling:** El canal de transmisión ahora transporta punteros a lotes de paquetes (`*TxBatch`) en lugar de paquetes individuales. Reduce la sobrecarga de sincronización de canales y del Scheduler de Go en un factor de 64x.

### 🛠 Compatibilidad
- **Multi-Platform Ready:** La adopción de la librería de WireGuard prepara el terreno para soporte nativo de alto rendimiento en Windows (Wintun) y macOS (Utun) en futuras versiones.

---

## [v0.8.0] - Usability & Automation (Fase 8)
### 🛠 Usabilidad y Sistema
- **Zero-Config Start:** Automatización completa de la configuración de red (IP/MTU) mediante interacción directa con el Kernel (Netlink). Elimina la necesidad de scripts `ip addr add` manuales.
- **Configuración Estructurada:** Soporte híbrido para archivos `config.toml` y Flags. Implementado con `go-toml/v2` para evitar overhead de reflexión y mantener el binario ligero.
- **Graceful Shutdown:** Manejo robusto de señales (`SIGINT`, `SIGTERM`) para garantizar el cierre limpio de sockets y descriptores de archivo, evitando corrupción de datos o estados inconsistentes en la interfaz TUN.

### ⚡ Rendimiento
- **Cold Path Isolation:** la mayor parte del parsing/configuración ocurre antes del motor. La cifra histórica de ~940 Mbps no se usa como garantía actual; ver `docs/PERFORMANCE.md`.

---

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
- La versión de entonces documentó una meta de zero-allocation en RX. La medición actual sólo confirma 0 allocs/op en parser/encoder; session seal/open mide 1 alloc/op.
- Perfilado de CPU confirma que el tiempo de ejecución principal se ha desplazado de la gestión de memoria/runtime a las operaciones criptográficas y syscalls.

---

## [v0.5.0] - Multi-Core Scaling (Fase 5)
### ⚡ Concurrencia
- **SO_REUSEPORT:** Implementación de socket sharding en Linux. Permite múltiples descriptores de archivo en el mismo puerto UDP distribuidos por el Kernel.
- **Worker sharding:** el número de sockets/workers UDP se deriva de `runtime.NumCPU()` por defecto; no se fija afinidad de CPU explícita.
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
