# Taltun ⚡

![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)
![Platform](https://img.shields.io/badge/Linux-x86__64-linux?style=flat&logo=linux)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Status](https://img.shields.io/badge/Status-Beta%20%28v0.10.0%29-orange)
![Performance](https://img.shields.io/badge/Performance-~1Gbps-red)
[![Config Wizard](https://img.shields.io/badge/🪄_Config_Wizard-Generador_Web-blue?style=for-the-badge&logo=html5)](https://soyunomas.github.io/Taltun/)

> **¿Te da pereza configurar archivos a mano?** Usa nuestro [Generador de Configuración Web](https://soyunomas.github.io/Taltun/). Genera claves y archivos listos para copiar y pegar de forma segura (todo se ejecuta localmente en tu navegador).

**Taltun** es un motor VPN de próxima generación diseñado para el rendimiento extremo y la simplicidad operativa. Escrito en Go puro, utiliza técnicas avanzadas de **Kernel Bypass** (Userspace Networking), **Vectorized I/O** y **Lock-Free Concurrency** para saturar enlaces Gigabit en hardware modesto.

A diferencia de las VPNs tradicionales, Taltun opera como un **Switch Distribuido Cifrado**, permitiendo topologías Mesh, Hub & Spoke y Site-to-Site sin complejas configuraciones de firewall ni tablas de enrutamiento en el sistema operativo (gracias a su motor de Relay en espacio de usuario).

## 🚀 Características Principales

### ⚡ Rendimiento "Metal-Close"
- **Vectorized I/O:** Utiliza `recvmmsg` y `sendmmsg` (syscall batching) para procesar paquetes en bloques de 64, reduciendo el cambio de contexto CPU en un **98%**.
- **Zero-Copy Hot Path:** El tráfico reenviado (Relay) entre clientes no toca el Kernel ni copia memoria innecesariamente.
- **Multi-Core Scaling:** Distribuye la carga criptográfica y de I/O entre todos los núcleos disponibles usando `SO_REUSEPORT`.

### 🛡️ Seguridad Post-Quantum Ready
- **Noise Protocol Framework (Like):** Handshake basado en **Curve25519** (ECDH) y tráfico de datos cifrado con **ChaCha20-Poly1305**.
- **Perfect Forward Secrecy (PFS):** Las claves de cifrado rotan automáticamente cada 2 minutos.
- **Anti-Replay & DoS Protection:** Ventana deslizante de 2048 bits y Cookies Stateless para mitigar ataques de denegación de servicio.

### 🧠 Routing Inteligente (Nuevo en v0.10)
- **User-Space Relay:** Permite que dos clientes (Spokes) se comuniquen entre sí a través del servidor (Hub) sin necesidad de configurar `iptables` ni IP Forwarding en el servidor.
- **Subnet Routing:** Soporte completo para LANs. Un cliente puede anunciar una subred (ej. `192.168.1.0/24`) y el resto de la VPN podrá acceder a ella transparentemente.

---

## 📦 Instalación

### Requisitos Previos
*   **Linux:** Kernel 5.6+ recomendado (para optimizaciones UDP modernas).
*   **Go:** 1.22 o superior (si compilas desde el código fuente).

### Compilación desde Fuente

```bash
# 1. Clonar el repositorio
git clone https://github.com/soyunomas/Taltun.git
cd Taltun

# 2. Instalar dependencias
go mod tidy

# 3. Compilar (Binario optimizado sin símbolos de debug)
make build

# El ejecutable estará en ./bin/vpn
ls -lh bin/vpn
```

---

## 🔑 Generación de Claves

Taltun utiliza criptografía de clave pública. Cada nodo necesita un par de claves:
1.  **Clave Privada:** Se guarda en el archivo de configuración. **NUNCA la compartas.**
2.  **Clave Pública:** Se deriva de la privada. Esta es la que configuras en los otros nodos (Peers) para que te reconozcan.

Como Taltun usa el formato estándar de 32 bytes en Hexadecimal (Curve25519), puedes generar las claves usando `openssl`:

```bash
# Generar Clave Privada (Private Key)
openssl rand -hex 32
# Salida ejemplo: a1b2c3d4... (Guarda esto para tu config.toml)

# Nota: Taltun derivará automáticamente la pública al arrancar. 
# Si necesitas ver tu clave pública para dársela a otro, arranca Taltun y mira los logs,
# o usa herramientas compatibles con X25519.
```

---

## ⚙️ Configuración (TOML)

La forma recomendada de usar Taltun es mediante un archivo `config.toml`. A continuación se detalla cada parámetro.

### Estructura del Archivo

```toml
# config.toml - Ejemplo Completo

[interface]
# Rol del nodo: 'server' (espera conexiones) o 'client' (inicia conexiones)
mode = "client"

# Nombre de la interfaz virtual a crear
tun_name = "tun0"

# Puerto UDP donde escuchar tráfico cifrado
local_addr = "0.0.0.0:9000"

# IP Virtual (VIP) de este nodo dentro de la VPN
vip = "10.0.0.2"

# Tu Clave Privada (32 bytes hex)
private_key = "TU_CLAVE_PRIVADA_AQUI"

# MTU del túnel. 1380 es seguro para evitar fragmentación en la mayoría de redes.
mtu = 1380

# Rutas locales a inyectar en tu sistema operativo al arrancar.
# Define qué tráfico quieres que "entre" al túnel.
# "0.0.0.0/0" = Todo el tráfico (Full Tunnel)
# "10.0.0.0/24" = Solo tráfico de la VPN
routes = ["10.0.0.0/24", "192.168.50.0/24"]

# --- Definición de Peers (Nodos Remotos) ---

[[peers]]
# IP Virtual del nodo remoto
vip = "10.0.0.1"

# (Opcional) Dirección IP Pública y Puerto del remoto.
# Obligatorio si este nodo debe iniciar la conexión hacia él.
endpoint = "203.0.113.1:9000"

# (Nuevo v0.10) AllowedIPs: ¿Qué subredes están "detrás" de este peer?
# Permite Site-to-Site. Si envías tráfico a estas IPs, Taltun sabrá que debe enviárselo a este Peer.
allowed_ips = ["192.168.50.0/24"]
```

---

## 🖥️ Uso por Línea de Comandos (CLI)

Puedes sobrescribir cualquier valor del archivo de configuración usando argumentos (flags). Esto es útil para pruebas rápidas o scripts de docker.

```bash
# Ejemplo: Arrancar un servidor rápido escuchando en el puerto 4000
sudo ./bin/vpn \
  -mode server \
  -local "0.0.0.0:4000" \
  -vip "10.99.0.1" \
  -key "e6a1..." \
  -tun "tun5"
```

| Flag | Descripción |
| :--- | :--- |
| `-config` | Ruta al archivo TOML (Defecto: `config.toml`) |
| `-mode` | `client` o `server` |
| `-vip` | Tu IP dentro de la VPN |
| `-key` | Tu Clave Privada (Hex) |
| `-local` | `IP:Puerto` UDP local para escuchar |
| `-tun` | Nombre de la interfaz (ej. `tun0`) |
| `-mtu` | Maximum Transmission Unit (Defecto: 1420) |
| `-debug` | Activa logs detallados (verbose) |

---

## 🌐 Escenario Real: Red Empresarial (Hub & Spoke)

Vamos a configurar una red completa con 3 nodos para demostrar las capacidades de **Enrutamiento y Relay** de Taltun v0.10.

**El Objetivo:**
1.  **Servidor (Hub):** En la nube. Punto central.
2.  **Oficina (Gateway):** Expone la red LAN `192.168.50.0/24`.
3.  **Empleado (Remoto):** Desde su casa, quiere acceder a la impresora de la oficina (`192.168.50.10`).

### 1. Configuración del SERVIDOR (Hub)
*   **IP Pública:** 1.2.3.4
*   **VIP:** 10.0.0.1

```toml
# server.toml
[interface]
mode = "server"
tun_name = "tun0"
vip = "10.0.0.1"
local_addr = "0.0.0.0:9000"
private_key = "KEY_SERVER"
routes = ["10.0.0.0/24"] # El servidor necesita saber enrutar la VPN

# Peer: OFICINA
[[peers]]
vip = "10.0.0.2"
# "Detrás de la oficina está la red 192.168.50.x"
allowed_ips = ["192.168.50.0/24"] 

# Peer: EMPLEADO
[[peers]]
vip = "10.0.0.3"
```

---

### 2. Configuración de la OFICINA (Site Gateway)
*   **VIP:** 10.0.0.2
*   **Rol:** Gateway. Recibe tráfico de la VPN y lo saca a la red física.

⚠️ **REQUISITO CRÍTICO: NAT & Forwarding**
Para que los dispositivos de la oficina (impresoras, servidores) sepan responder a los paquetes que vienen de la VPN, el Gateway debe hacer **NAT (Masquerade)**. De lo contrario, los dispositivos recibirán el paquete pero no sabrán cómo devolver la respuesta a la IP `10.0.0.x`.

Ejecuta esto en el nodo Oficina:

```bash
# 1. Habilitar el reenvío de paquetes en el Kernel
sudo sysctl -w net.ipv4.ip_forward=1

# 2. Configurar NAT (Sustituye 'eth0' por tu interfaz física, ej: enp7s0)
# Esto hace que el tráfico VPN parezca venir de la IP local de este PC.
sudo iptables -t nat -A POSTROUTING -o eth0 -s 10.0.0.0/24 -j MASQUERADE

# 3. Permitir el paso de tráfico (Firewall)
sudo iptables -A FORWARD -i tun0 -o eth0 -j ACCEPT
sudo iptables -A FORWARD -i eth0 -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT
```

**Archivo `office.toml`:**

```toml
# office.toml
[interface]
mode = "client"
vip = "10.0.0.2"
local_addr = "0.0.0.0:9000"
private_key = "KEY_OFFICE"
routes = ["10.0.0.0/24"] # Enruta tráfico VPN

[[peers]]
# Conexión al Hub
vip = "10.0.0.1"
endpoint = "1.2.3.4:9000"
# Definimos "0.0.0.0/0" si queremos que TODA la red VPN sea accesible via el Hub
allowed_ips = ["10.0.0.0/24"]
```
### 3. Configuración del EMPLEADO (Road Warrior)
*   **VIP:** 10.0.0.3

```toml
# laptop.toml
[interface]
mode = "client"
vip = "10.0.0.3"
private_key = "KEY_EMPLOYEE"
# ¡MAGIA AQUÍ! 
# Le decimos al OS del empleado: "Para ir a la 192.168.50.x, entra al túnel"
routes = ["10.0.0.0/24", "192.168.50.0/24"]

[[peers]]
# Conexión al Hub
vip = "10.0.0.1"
endpoint = "1.2.3.4:9000"
# Le decimos al motor Taltun del empleado: 
# "Si envías algo a la 192.168.50.x, envíaselo a este Peer (al Hub)"
allowed_ips = ["192.168.50.0/24","10.0.0.0/24"]
```

### 🎯 Resultado
El empleado hace `ping 192.168.50.10`:
1.  El paquete entra a Taltun en el Laptop.
2.  Se envía cifrado al **Servidor**.
3.  El Servidor lo desencripta, ve que es para la subred de la **Oficina**.
4.  El Servidor lo **Re-encripta** (User-Space Relay) y lo manda a la **Oficina**.
5.  La Oficina lo recibe y lo entrega a la impresora.

---

## ⚡ Tuning de Rendimiento

Para alcanzar velocidades Gigabit, se recomienda ajustar los buffers del Kernel en Linux (sysctl):

```bash
# Aumentar buffers de recepción/envío UDP
sysctl -w net.core.rmem_max=4194304
sysctl -w net.core.wmem_max=4194304
sysctl -w net.core.rmem_default=262144
sysctl -w net.core.wmem_default=262144
```

Además, si usas Taltun detrás de routers domésticos (PPPoE), ajusta el **TCP MSS** para evitar paquetes descartados por fragmentación:

```bash
sudo iptables -t mangle -A FORWARD -o tun0 -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
```

---

## 🛠️ Arquitectura Interna

Taltun no es solo "otro wrapper de UDP". Su arquitectura está diseñada para la eficiencia:

1.  **TUN Device:** Lee paquetes IP del Kernel.
2.  **Worker Pool:** Un pool de goroutines cifra los paquetes usando instrucciones AES/AVX.
3.  **Batcher:** Agrupa hasta 64 paquetes cifrados en una sola estructura.
4.  **Vectorized Writer:** Envía el lote completo al socket UDP usando `sendmmsg`.

Este pipeline minimiza las "System Calls", que son el principal cuello de botella en VPNs tradicionales escritas en Go o Python.

---

## 📄 Licencia

Este proyecto es Open Source bajo la licencia **MIT**. Siéntete libre de usarlo, modificarlo y contribuir.

---
