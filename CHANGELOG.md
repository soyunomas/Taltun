# Changelog - Taltun

Todos los cambios notables en el proyecto Taltun serán documentados en este archivo.

## [v0.11.0] - Lighthouse & Hole Punching (Fase 11)
### 🕯️ Lighthouse Mode & Discovery
- **Lighthouse Role:** Introducción del modo `lighthouse` en la configuración. Este modo opera exclusivamente en espacio de usuario (sin interfaz TUN), actuando como un faro de señalización y relay de respaldo.
- **Peer Signaling Protocol:** Implementación del nuevo mensaje `MsgTypePeerUpdate`. Permite al faro notificar a los clientes sobre la ubicación IP pública de sus pares para iniciar conexiones directas.
- **Hole Punching Asistido:** Lógica de "Simultaneous Open". Cuando dos clientes intentan comunicarse a través del Faro, este instruye a ambos para que inicien un Handshake agresivo entre sí, perforando los NATs simétricos/estáticos.
- **Route Promotion:** El motor ahora soporta peers "flotantes" (sin endpoint inicial). Al completarse un handshake exitoso y validado, el motor "promociona" la ruta, instalando una entrada `/32` directa y dejando de usar el Faro como relay.

### 🛠️ Correcciones y Estabilidad
- **Panic Fix:** Solucionado un error crítico donde el motor intentaba escribir en una interfaz TUN inexistente cuando operaba en modo `lighthouse`.
- **Concurrency Safety:** Corrección de una Race Condition en el limitador de tasa de notificaciones (`ShouldNotify`) mediante el uso de contadores atómicos (`atomic.Int64`) en lugar de `time.Time` no protegido.
- **Fallback Routing:** Los peers sin endpoint configurado ahora enrutan por defecto hacia el Gateway/Faro hasta que se descubre la ruta directa.

---

## [v0.10.0] - Internal Switching & Relay (Fase 10)
... (resto del archivo sin cambios)
### 🔀 Advanced Routing (Routing V2)
- **Radix Trie (LPM):** Reemplazo del mapa plano `map[uint32]*Peer` por una estructura de datos de árbol (`Radix Tree`) optimizada para IPv4. Permite búsquedas de prefijos CIDR (Longest Prefix Match), habilitando arquitecturas **Site-to-Site** donde un peer da acceso a toda una subred (ej. `192.168.1.0/24`).
- **User-Space Relay (Hairpinning):** Implementación de lógica de conmutación interna. Si un paquete recibido por el servidor tiene como destino otro peer conectado, Taltun lo re-encripta y reenvía directamente en el espacio de usuario.
    - Evita el coste de cambios de contexto (TUN Write -> Kernel Routing -> TUN Read).
    - Permite comunicación **Client-to-Client** sin necesidad de configurar `ip forwarding` o `iptables` en el host.
- **AllowedIPs:** Nueva directiva de configuración para definir qué rangos de IP (CIDRs) se permiten y enrutan a través de cada peer.

### 🏗️ Engineering Refinements
- **Stack Allocation Optimization:** Eliminación de asignaciones en el Heap (`mallocgc`) para los buffers criptográficos (Nonce) en el ciclo de transmisión crítico. Reduce drásticamente la presión sobre el Garbage Collector bajo carga alta.
- **Engine Modularization:** Refactorización del núcleo monolítico en unidades lógicas (`dataplane_rx`, `dataplane_tx`, `control`, `types`) para mejorar la mantenibilidad y legibilidad del código base.

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
- **Zero-Copy Header Prepend:** Uso de *Offset Reads* para reservar espacio de cabecera (`Headroom`) en el buffer antes de leer del Kernel. Permite encapsular el paquete IP sin mover la memoria (`memcpy` eliminado en el path crítico de TX).

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
- **Cold Path Isolation:** Toda la lógica de parsing y configuración se ejecuta estrictamente antes de iniciar el motor. El *hot-path* (ciclo de transmisión) permanece intocado, manteniendo el rendimiento de **~940 Mbps**.

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
