Aquí tienes un **README.md** profesional, estructurado al estilo de proyectos de infraestructura modernos como Tailscale o WireGuard. Está diseñado para destacar tanto la facilidad de uso como la profundidad técnica del proyecto.

Copia el siguiente bloque en tu archivo `README.md`.

---

# Taltun ⚡

![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)
![Platform](https://img.shields.io/badge/Linux-x86__64-linux?style=flat&logo=linux)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Status](https://img.shields.io/badge/Status-Stable%20%28v0.7.0%29-blue)

**Taltun** es una VPN de alto rendimiento, *Zero-Allocation* y segura, escrita en Go puro. Diseñada para saturar enlaces Gigabit en hardware modesto mediante el uso intensivo de **Vectorized I/O**, **SIMD Cryptography** y **Kernel Bypass techniques** (userspace networking).

A diferencia de las VPNs tradicionales que sufren de latencia por cambios de contexto y asignación de memoria dinámica, Taltun implementa un dataplane optimizado que mueve paquetes directamente entre el Kernel y la memoria de la aplicación con un overhead mínimo.

---

## 🚀 ¿Por qué Taltun?

### ⚡ Rendimiento Extremo
- **Gigabit Speed:** Capaz de sostener **~940 Mbps** (saturación de enlace) en hardware legacy (Intel Haswell i5, 2013).
- **Vectorized I/O:** Usa `recvmmsg` y `sendmmsg` para leer y escribir paquetes en lotes de 64, reduciendo las System Calls en un **98%**.
- **Multi-Core Scaling:** Implementa `SO_REUSEPORT` y *Socket Sharding* para distribuir la carga entre todos los núcleos de la CPU sin contención de locks.

### 🛡️ Seguridad Moderna
- **Cifrado Robusto:** Todo el tráfico de datos usa **ChaCha20-Poly1305** con aceleración por hardware (AVX2).
- **Perfect Forward Secrecy (PFS):** Handshake basado en **ECDH (Curve25519)**. Las claves de sesión son efímeras y únicas por peer.
- **Identidad Criptográfica:** Autenticación mutua estricta basada en claves públicas, sin contraseñas.

### 🧠 Ingeniería Eficiente
- **Zero-Allocation Hot Path:** El bucle de transmisión de datos no genera basura (0% GC overhead), eliminando latencias impredecibles.
- **Smart Caching:** Caché L1 por software para enrutamiento (`RX Peer Caching`), optimizado para flujos de datos de alta velocidad (streaming, descargas).

---

## 📦 Instalación

### Prerrequisitos
- **Sistema Operativo:** Linux (Kernel 5.x+ recomendado para mejor soporte de BPF/recvmmsg).
- **Go:** Versión 1.22 o superior.

### Compilación desde el código fuente

```bash
# 1. Clonar el repositorio
git clone https://github.com/tu-usuario/taltun.git
cd taltun

# 2. Compilar binario optimizado (Strip debug symbols + O3 equivalent)
make build

# El binario estará disponible en: ./bin/vpn
ls -lh bin/vpn
```

---

## 🛠️ Puesta en Marcha (Quickstart)

Taltun utiliza una arquitectura **Hub & Spoke** (aunque el protocolo soporta P2P). Simularemos una red simple:
- **Servidor (Hub):** IP Real `203.0.113.1` | IP VPN `10.0.0.1`
- **Cliente (Spoke):** IP Dinámica | IP VPN `10.0.0.2`

### Paso 0: Generar Claves
Necesitas una clave privada hexadecimal de 32 bytes (64 caracteres) para cada nodo.

```bash
# Generar clave para el Servidor
openssl rand -hex 32
# Salida ejemplo: aaaa... (KEY_SERVER)

# Generar clave para el Cliente
openssl rand -hex 32
# Salida ejemplo: bbbb... (KEY_CLIENT)
```

### Paso 1: Configurar el Servidor

En la máquina servidor (ej. AWS, VPS, o local):

```bash
# Iniciar Taltun en modo Server
# -local: Puerto UDP donde escuchará
# -vip: La IP virtual que tendrá este nodo dentro de la VPN
sudo ./bin/vpn \
  -mode server \
  -local "0.0.0.0:9000" \
  -tun tun0 \
  -key "TU_KEY_SERVER_HEX" \
  -vip "10.0.0.1"

# En otra terminal, asigna la IP a la interfaz (esto se automatizará en v1.0)
sudo ip addr add 10.0.0.1/24 dev tun0
sudo ip link set up dev tun0
```

### Paso 2: Configurar el Cliente

En tu ordenador local:

```bash
# Iniciar Taltun en modo Client
# -peer: Define a quién conectarse. Formato: VIP_DESTINO,IP_FISICA:PUERTO
sudo ./bin/vpn \
  -mode client \
  -local "0.0.0.0:0" \
  -tun tun0 \
  -key "TU_KEY_CLIENT_HEX" \
  -vip "10.0.0.2" \
  -peer "10.0.0.1,203.0.113.1:9000"

# Asignar IP a la interfaz
sudo ip addr add 10.0.0.2/24 dev tun0
sudo ip link set up dev tun0
```

### Paso 3: Verificar Conectividad

Desde el cliente:
```bash
ping 10.0.0.1
```
*¡Deberías ver respuesta con latencia mínima!*

---

## ⚙️ Arquitectura Técnica

### Flujo de Datos (TX Path)
1. **TUN Read:** El kernel entrega un paquete IP crudo a la aplicación.
2. **Encryption (Worker A):** Una goroutine lee, decide el enrutamiento y cifra el paquete (ChaCha20).
3. **Queueing:** El paquete cifrado se envía a un canal (`buffered channel`).
4. **Batch Write (Worker B):** Una segunda goroutine recoge hasta 64 paquetes del canal y usa `sendmmsg` para enviarlos al socket UDP en una sola llamada al sistema.

### Handshake (Noise_NK Pattern)
1. **Init:** Cliente envía su clave pública efímera + identidad cifrada con la clave pública estática del servidor.
2. **Response:** Servidor valida, genera su clave efímera y calcula el secreto compartido ECDH.
3. **Session:** Se deriva una clave simétrica con `Blake2s`. A partir de aquí, el tráfico es puramente simétrico y acelerado.

---

## 🧪 Benchmarks y Desarrollo

Para ejecutar las pruebas de integración que simulan una red completa en tu máquina local usando Linux Namespaces:

```bash
# Requiere sudo para crear interfaces veth/tun
make integration
```

Para ver el perfil de CPU en tiempo real durante un test de carga:
```bash
go tool pprof -http=:8080 cpu.prof
```

---

## 🔮 Roadmap & TO-DO

El core de alto rendimiento está completo (v0.7.0). Los siguientes pasos se centran en usabilidad y expansión de plataforma.

### Corto Plazo (v0.8 - v0.9)
- [ ] **Config Files:** Soporte para archivos `config.yaml` o `config.toml` para evitar flags largos.
- [ ] **IPAM Automático:** Asignación automática de IPs en la interfaz TUN al iniciar (eliminar necesidad de `ip addr add` manual).
- [ ] **Rekeying:** Rotación automática de claves de sesión cada X minutos o N gigabytes.
- [ ] **Cross-Platform:** Soporte inicial para macOS (usando `utun`) y Windows (usando `wintun`).

### Largo Plazo (v1.0+)
- [ ] **Full Mesh P2P:** Implementación de STUN/UDP Hole Punching para conexión directa entre clientes sin pasar por el servidor.
- [ ] **eBPF / XDP Offload:** Mover el filtrado y enrutamiento directamente al driver de red para saltarse el stack TCP/IP completamente.
- [ ] **Control Panel:** Una API REST simple para gestionar peers autorizados dinámicamente.
- [ ] **Anti-Replay Window:** Protección avanzada contra ataques de repetición usando bit-sliding windows.

---

## 📄 Licencia

Este proyecto está bajo la Licencia **MIT**. Eres libre de usarlo, modificarlo y distribuirlo.

---
*Built with ❤️ and excessive amounts of coffee by [Soyunomas].*
