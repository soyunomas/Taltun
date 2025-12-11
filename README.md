# Taltun ⚡

![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)
![Platform](https://img.shields.io/badge/Linux-x86__64-linux?style=flat&logo=linux)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Status](https://img.shields.io/badge/Status-Stable%20%28v0.8.0%29-blue)

**Taltun** es una VPN de alto rendimiento, Zero-Allocation y segura, escrita en Go puro. Optimizada para aprovechar la totalidad del ancho de banda en enlaces Gigabit sobre hardware modesto, mediante el uso intensivo de Vectorized I/O, SIMD Cryptography y Kernel Bypass techniques (userspace networking).

---

## 🚀 ¿Por qué Taltun?

### ⚡ Rendimiento Extremo
- **Gigabit Speed:** Capaz de sostener **~940 Mbps** (saturación de enlace) en hardware legacy.
- **Vectorized I/O:** Usa `recvmmsg` y `sendmmsg` para leer y escribir paquetes en lotes de 64, reduciendo las System Calls en un **98%**.
- **Multi-Core Scaling:** Implementa `SO_REUSEPORT` y *Socket Sharding* para distribuir la carga entre todos los núcleos de la CPU sin contención de locks.

### 🛠 Usabilidad y Automatización (Nuevo en v0.8)
- **Zero-Config Start:** Asignación automática de IPs y configuración de MTU via Netlink. No requiere scripts externos.
- **Structured Config:** Soporte nativo para archivos TOML limpios.
- **Kernel Routing:** Inyección automática de rutas estáticas al levantar el túnel.
- **Graceful Shutdown:** Cierre seguro de recursos y limpieza de rutas al detener el servicio.

### 🛡️ Seguridad Moderna
- **Cifrado Robusto:** Todo el tráfico de datos usa **ChaCha20-Poly1305** con aceleración por hardware (AVX2).
- **Perfect Forward Secrecy (PFS):** Handshake basado en **ECDH (Curve25519)**. Las claves de sesión son efímeras y únicas por peer.
- **Identidad Criptográfica:** Autenticación mutua estricta basada en claves públicas, sin contraseñas.

---

## 📦 Instalación

### Prerrequisitos
- **Sistema Operativo:** Linux (Kernel 5.x+ recomendado para mejor soporte de BPF/recvmmsg).
- **Go:** Versión 1.22 o superior.

### Compilación desde el código fuente

```bash
# 1. Clonar el repositorio
git clone https://github.com/soyunomas/taltun.git
cd taltun

# 2. Descargar dependencias
go mod tidy

# 3. Compilar binario optimizado
make build

# El binario estará disponible en: ./bin/vpn
ls -lh bin/vpn
```

---

## ⚙️ Configuración (v0.8.0+)

Taltun soporta archivos de configuración TOML para facilitar despliegues complejos. Crea un archivo `config.toml`:

```toml
# config.toml
[interface]
mode = "server"             # client | server
tun_name = "tun0"           # Nombre interfaz
vip = "10.0.0.1"            # IP VPN
local_addr = "0.0.0.0:9000" # Puerto UDP escucha
private_key = "TU_PRIVATE_KEY_HEX"

# Rutas Estáticas (Kernel Injection)
# Define qué subredes deben pasar por la VPN.
# Si está vacío, solo pasa el tráfico a la IP del peer.
routes = ["192.168.50.0/24"]

# Lista de Peers (Clientes o Servidores)
[[peers]]
vip = "10.0.0.2"
# endpoint = "x.x.x.x:9000" # Opcional si es dinámico
```

### 🛣️ Caso Especial: Full Tunneling (Todo por la VPN)

Si quieres redirigir todo tu tráfico de internet por la VPN pero **sin perder el acceso a tu red local (SSH)**, usa esta configuración de rutas en lugar de `0.0.0.0/0`:

```toml
# Inyecta dos rutas /1 que cubren todo el espectro IPv4 pero respetan las rutas locales más específicas.
routes = ["0.0.0.0/1", "128.0.0.0/1"]
```

---

## 🛠️ Puesta en Marcha (Quickstart)

Taltun utiliza una arquitectura **Hub & Spoke**. Simularemos una red simple:
- **Servidor (Hub):** IP VPN `10.0.0.1`
- **Cliente (Spoke):** IP VPN `10.0.0.2`

### Paso 0: Generar Claves

```bash
openssl rand -hex 32
# Guarda la salida para usarla como clave privada (-key)
```

### Paso 1: Configurar el Servidor

```bash
# Iniciar Taltun en modo Server
# Nota: Taltun configurará automáticamente la IP en la interfaz tun0.
sudo ./bin/vpn \
  -mode server \
  -local "0.0.0.0:9000" \
  -key "TU_KEY_SERVER_HEX" \
  -vip "10.0.0.1"
```

### Paso 2: Configurar el Cliente

En otra máquina:

```bash
# Iniciar Taltun en modo Client
# Conectándose al peer (Servidor)
sudo ./bin/vpn \
  -mode client \
  -key "TU_KEY_CLIENT_HEX" \
  -vip "10.0.0.2" \
  -peer "10.0.0.1,IP_REAL_SERVIDOR:9000"
```

### Paso 3: Verificar Conectividad

Desde el cliente:
```bash
ping 10.0.0.1
```
*¡Deberías ver respuesta con latencia mínima!*

---

## ⚡ Performance Tuning

Para evitar la fragmentación en enlaces WAN (especialmente en modo Full Tunnel), se recomienda configurar **TCP MSS Clamping** en el firewall:

```bash
# Ajusta el tamaño de segmento TCP al MTU del túnel automáticamente
sudo iptables -t mangle -A FORWARD -o tun0 -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
```

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

## 📄 Licencia

Este proyecto está bajo la Licencia **MIT**. Eres libre de usarlo, modificarlo y distribuirlo.
