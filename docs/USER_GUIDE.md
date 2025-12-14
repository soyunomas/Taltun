# 📘 Manual de Operaciones Taltun v0.10.0

Este documento detalla la instalación, configuración y despliegue de Taltun en diferentes topologías de red, aprovechando las nuevas capacidades de enrutamiento y relay de la versión 0.10.0.

## 📑 Índice de Contenidos

1.  [Preparación del Entorno](#1-preparación-del-entorno)
    *   [1.1. Requisitos del Sistema](#11-requisitos-del-sistema)
    *   [1.2. Compilación del Binario](#12-compilación-del-binario)
    *   [1.3. Tuning del Kernel para Alto Rendimiento](#13-tuning-del-kernel-para-alto-rendimiento)
    *   [1.4. Generación de Claves](#14-generación-de-claves)
2.  [Arquitectura de Configuración](#2-arquitectura-de-configuración)
    *   [2.1. Anatomía de config.toml](#21-anatomía-de-configtoml)
    *   [2.2. Diferencia entre vip y endpoint](#22-diferencia-entre-vip-y-endpoint)
    *   [2.3. Lógica de Enrutamiento v0.10](#23-lógica-de-enrutamiento-v010)
3.  [Escenarios de Despliegue (Recetario)](#3-escenarios-de-despliegue-recetario)
    *   [3.1. Escenario A: Conexión Básica (Cliente-Servidor)](#31-escenario-a-conexión-básica-cliente-servidor)
    *   [3.2. Escenario B: Road Warrior (Hub & Spoke)](#32-escenario-b-road-warrior-hub--spoke)
    *   [3.3. Escenario C: Full Tunnel & Privacidad (Internet Exit)](#33-escenario-c-full-tunnel--privacidad-internet-exit)
    *   [3.4. Escenario D: Site-to-Site (LAN Extension)](#34-escenario-d-site-to-site-lan-extension)
    *   [3.5. Escenario E: Client-to-Client Relay](#35-escenario-e-client-to-client-relay)
4.  [Puesta en Producción](#4-puesta-en-producción)
    *   [4.1. Creación de Servicio systemd](#41-creación-de-servicio-systemd)
    *   [4.2. Monitorización de Logs y Debugging](#42-monitorización-de-logs-y-debugging)

---

## 1. Preparación del Entorno

Antes de configurar la VPN, es crítico preparar el sistema operativo anfitrión. Taltun es un motor de alto rendimiento que opera en *User Space*, pero depende fuertemente de la configuración de red del Kernel de Linux para alcanzar velocidades Gigabit.

### 1.1. Requisitos del Sistema

*   **Sistema Operativo:** Linux (x86_64 o ARM64).
    *   *Recomendado:* Kernel 5.6 o superior (para soporte óptimo de syscalls `recvmmsg`/`sendmmsg`).
*   **Red:**
    *   Una dirección IP pública accesible (para el nodo Servidor/Hub).
    *   **Puerto UDP:** Debes abrir el puerto **9000** (UDP) en tu firewall (UFW, iptables, AWS Security Groups).
*   **Permisos:** Se requieren privilegios de `root` (o capacidad `CAP_NET_ADMIN`) para crear la interfaz virtual TUN.

### 1.2. Compilación del Binario

Actualmente, se recomienda compilar Taltun desde el código fuente para asegurar la compatibilidad con la arquitectura del CPU local (aprovechando instrucciones AES/AVX nativas).

**Prerrequisitos:** Tener instalado [Go 1.22+](https://go.dev/dl/).

```bash
# 1. Clonar el repositorio
git clone https://github.com/soyunomas/Taltun.git
cd Taltun

# 2. Descargar dependencias
go mod tidy

# 3. Compilar versión optimizada (Production Build)
# El Makefile generará un binario ligero sin símbolos de depuración.
make build

# 4. Verificar instalación
# El ejecutable se ubicará en ./bin/vpn
./bin/vpn -help
```

### 1.3. Tuning del Kernel para Alto Rendimiento

Para evitar que el Kernel de Linux descarte paquetes UDP durante ráfagas de tráfico intenso (Bufferbloat), es necesario ajustar los buffers de red. Además, si el nodo va a actuar como Gateway (Escenarios C y D), se debe habilitar el reenvío de IP.

Crea el archivo `/etc/sysctl.d/99-taltun.conf`:

```ini
# --- Taltun Performance Tuning ---

# Aumentar buffers de recepción/envío UDP a 4MB
# (Crucial para soportar tráfico > 500 Mbps sin packet loss)
net.core.rmem_max=4194304
net.core.wmem_max=4194304
net.core.rmem_default=262144
net.core.wmem_default=262144

# Habilitar IP Forwarding
# (Obligatorio para que la VPN actúe como Router/Gateway)
net.ipv4.ip_forward=1
```

Aplica los cambios sin reiniciar:

```bash
sudo sysctl -p /etc/sysctl.d/99-taltun.conf
```

### 1.4. Generación de Claves

Taltun utiliza criptografía de Curva Elíptica (X25519). Las claves son cadenas hexadecimales de 32 bytes.

Cada nodo necesita su propio par de claves:
1.  **Private Key:** Se define en el archivo de configuración local. **NUNCA debe compartirse.**
2.  **Public Key:** Se deriva automáticamente de la privada. Esta es la que debes configurar en los nodos remotos (Peers) para que te reconozcan.

Puedes generar una clave privada segura usando `openssl`:

```bash
# Generar una clave aleatoria de 32 bytes en Hex
openssl rand -hex 32
```

> **Salida de ejemplo:** `a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef12345678`
>
> *Copia esta cadena. La necesitarás para el parámetro `private_key` en el siguiente paso.*

```bash
# --- BLOQUE LOCAL (Tu Identidad) ---
[interface]
mode = "client"                  # Rol: 'client' (inicia) o 'server' (escucha)
tun_name = "tun0"                # Nombre de la interfaz virtual
vip = "10.0.0.2"                 # Tu IP dentro de la VPN (Overlay)
local_addr = "0.0.0.0:9000"      # Puerto UDP local para escuchar
private_key = "TU_CLAVE_PRIVADA" # Generada en paso 1.4

# Rutas del Sistema Operativo (OS Routing)
# ¿Qué tráfico de tu PC debe entrar al túnel?
routes = ["10.0.0.0/24"]         

# --- BLOQUE REMOTO (Tus Contactos) ---
[[peers]]
vip = "10.0.0.1"                 # IP VPN del remoto
endpoint = "203.0.113.1:9000"    # IP Pública:Puerto (Opcional si eres server)

# Rutas Internas de Taltun (Engine Routing) - NUEVO EN v0.10
# ¿Qué tráfico se permite venir de este peer?
# ¿Hacia qué IPs detrás de este peer debemos enviar tráfico?
allowed_ips = ["10.0.0.0/24", "192.168.1.0/24"]
```
## 2. Arquitectura de Configuración

Taltun se configura mediante un único archivo TOML (por defecto `config.toml`). Entender la lógica de este archivo es fundamental para desplegar topologías complejas.

### 2.1. Anatomía de config.toml

El archivo se divide en dos bloques principales:
1.  **`[interface]`**: Define la identidad y comportamiento del nodo local.
2.  **`[[peers]]`**: Lista de nodos remotos autorizados.

```toml
# --- BLOQUE LOCAL (Tu Identidad) ---
[interface]
mode = "client"                  # Rol: 'client' (inicia) o 'server' (escucha)
tun_name = "tun0"                # Nombre de la interfaz virtual
vip = "10.0.0.2"                 # Tu IP dentro de la VPN (Overlay)
local_addr = "0.0.0.0:9000"      # Puerto UDP local para escuchar
private_key = "TU_CLAVE_PRIVADA" # Generada en paso 1.4

# Rutas del Sistema Operativo (OS Routing)
# ¿Qué tráfico de tu PC debe entrar al túnel?
routes = ["10.0.0.0/24"]         

# --- BLOQUE REMOTO (Tus Contactos) ---
[[peers]]
vip = "10.0.0.1"                 # IP VPN del remoto
endpoint = "203.0.113.1:9000"    # IP Pública:Puerto (Opcional si eres server)

# Rutas Internas de Taltun (Engine Routing) - NUEVO EN v0.10
# ¿Qué tráfico se permite venir de este peer?
# ¿Hacia qué IPs detrás de este peer debemos enviar tráfico?
allowed_ips = ["10.0.0.0/24", "192.168.1.0/24"]
```

### 2.2. Diferencia entre vip y endpoint

Es crucial distinguir entre las dos capas de direccionamiento:

*   **VIP (Virtual IP):** Es la dirección IP interna del túnel (ej. `10.0.0.2`).
    *   Pertenece a la red "Overlay".
    *   Es constante y nunca cambia, incluso si el usuario se mueve de WiFi a 4G.
    *   Se usa para hacer `ping` y conectar servicios dentro de la VPN.

*   **Endpoint:** Es la dirección IP Pública real e Internet (ej. `203.0.113.1:9000`).
    *   Pertenece a la red "Underlay" (Internet física).
    *   **En Clientes:** Debes especificar el endpoint del Servidor para saber dónde llamar.
    *   **En Servidores:** Generalmente se deja vacío. El servidor "aprende" dinámicamente el endpoint del cliente cuando recibe el primer paquete autenticado válido (Roaming).

### 2.3. Lógica de Enrutamiento

Hay una distinción estricta entre enrutamiento del OS y enrutamiento interno del motor.

#### A. `routes` (Configuración del Sistema Operativo)
*   **Dónde:** Bloque `[interface]`.
*   **Función:** Ejecuta comandos `ip route add` en el host Linux al arrancar.
*   **Propósito:** Le dice a tu PC: *"Si quieres ir a estas IPs, envía el paquete a la interfaz `tun0`"*.
*   **Ejemplo:** `routes = ["0.0.0.0/0"]` redirige TODO el tráfico de internet hacia Taltun.

#### B. `allowed_ips` (Seguridad y Switching Interno)
*   **Dónde:** Bloque `[[peers]]`.
*   **Función:** Configura la tabla de enrutamiento interna (Radix Trie) del motor Taltun.
*   **Propósito (Doble):**
    1.  **Firewall de Entrada:** Si llega un paquete desde este Peer con una IP de origen que NO está en `allowed_ips`, Taltun lo descarta. Evita suplantación de identidad (Spoofing).
    2.  **Tabla de Salida:** Cuando Taltun tiene un paquete para enviar a la IP `192.168.1.50`, busca en su tabla qué Peer tiene `192.168.1.0/24` en sus `allowed_ips` y se lo envía a él.

> **Regla de Oro:** Para que el tráfico fluya, las rutas deben coincidir en ambos lados. El OS debe enviar el paquete al túnel (`routes`) y el Motor debe saber a qué Peer entregárselo (`allowed_ips`).

## 3. Escenarios de Despliegue (Recetario)

Esta sección describe configuraciones prácticas para casos de uso reales. Cada escenario incluye ejemplos de lo que el usuario podrá hacer una vez desplegado.

### 3.1. Escenario A: Conexión Básica (Cliente-Servidor)

El caso de uso más simple: conectar un nodo iniciador (ej. Laptop personal) contra un nodo receptor (ej. Servidor VPS o Raspberry Pi en casa).

**Casos de Uso Típicos:**
*   **Gestión Remota Segura:** Un administrador de sistemas accede por SSH a su servidor privado sin exponer el puerto 22 a internet.
*   **Acceso a Base de Datos:** Un desarrollador conecta su herramienta local (DBeaver, TablePlus) a la base de datos MySQL/PostgreSQL del servidor a través de la IP privada `10.0.0.1`, evitando exponer la DB a la red pública.
*   **Panel de Control:** Acceder al panel de administración web (ej. Portainer, Webmin) que solo escucha en `localhost` o en la interfaz VPN.

**Topología:**
*   **Servidor (VPS):** IP Pública `1.2.3.4`. VIP `10.0.0.1`.
*   **Cliente (Laptop):** Sin IP fija (NAT). VIP `10.0.0.2`.

**Configuración Servidor (`server.toml`)**
```toml
[interface]
mode = "server"
vip = "10.0.0.1"
local_addr = "0.0.0.0:9000"
private_key = "KEY_SERVER"

[[peers]]
vip = "10.0.0.2" # Cliente autorizado
# Endpoint vacío: Esperamos a que él nos llame.
```

**Configuración Cliente (`client.toml`)**
```toml
[interface]
mode = "client"
vip = "10.0.0.2"
private_key = "KEY_CLIENT"
routes = ["10.0.0.1/32"] # Solo queremos hablar con el server

[[peers]]
vip = "10.0.0.1"
endpoint = "1.2.3.4:9000" # IP Pública del VPS
allowed_ips = ["10.0.0.1/32"]
```

### 3.2. Escenario B: Road Warrior (Hub & Spoke)

Una arquitectura típica empresarial donde un servidor central (Hub) conecta a múltiples empleados o dispositivos remotos (Spokes) dispersos geográficamente.

**Casos de Uso Típicos:**
*   **Intranet Corporativa:** Los empleados remotos pueden acceder al Wiki interno, CRM o ERP alojado en la sede central (`10.0.0.1`) desde cualquier cafetería o casa.
*   **Compartición de Archivos (SMB/NFS):** Un diseñador gráfico en remoto puede montar una unidad de red alojada en el servidor de archivos de la oficina para subir su trabajo.
*   **Soporte Remoto (VNC/RDP):** El equipo de IT puede conectarse al escritorio remoto del portátil de un empleado (`10.0.0.3`) para solucionar un problema, siempre que el tráfico entre clientes esté permitido.

**Topología:**
*   **Hub (Sede Central):** VIP `10.0.0.1`. IP Pública Fija.
*   **Empleado 1 (Ventas):** VIP `10.0.0.2`.
*   **Empleado 2 (IT):** VIP `10.0.0.3`.

**Configuración Hub (`hub.toml`)**
```toml
[interface]
mode = "server"
vip = "10.0.0.1"
local_addr = "0.0.0.0:9000"
private_key = "KEY_HUB"

[[peers]]
vip = "10.0.0.2" # Empleado Ventas

[[peers]]
vip = "10.0.0.3" # Empleado IT
```

**Configuración Empleado (`laptop.toml`)**
```toml
[interface]
mode = "client"
vip = "10.0.0.2" # (Cambiar a .3 para el otro empleado)
private_key = "KEY_EMPLEADO"
# Ruta hacia toda la subred VPN. Permite ver al servidor y a otros compañeros.
routes = ["10.0.0.0/24"] 

[[peers]]
vip = "10.0.0.1"
endpoint = "HUB_PUBLIC_IP:9000"
# AllowedIPs: Permitimos recibir tráfico de cualquier IP de la VPN (Hub u otros empleados)
allowed_ips = ["10.0.0.0/24"]
```

### 3.3. Escenario C: Full Tunnel & Privacidad (Internet Exit)

En este modelo, el cliente redirige **todo** su tráfico de internet a través del túnel cifrado hacia el servidor, el cual actúa como puerta de salida a internet.

**Casos de Uso Típicos:**
*   **Seguridad en WiFi Pública:** Un usuario conectado al WiFi abierto de un aeropuerto o hotel activa Taltun. Todo su tráfico (bancos, correo, redes sociales) viaja cifrado hasta su servidor seguro, impidiendo que hackers locales espíen sus datos.
*   **Evasión de Geobloqueo:** Un usuario en un país con censura o restricciones geográficas conecta a un servidor Taltun en otro país para acceder a servicios de streaming o noticias bloqueadas.
*   **IP Fija para Servicios Cloud:** Un desarrollador necesita acceder a un servidor AWS que solo permite conexiones desde una IP específica. Al usar Full Tunnel, sale a internet con la IP del servidor VPN, cumpliendo el requisito de lista blanca.

**Requisito Previo en Servidor:**
El servidor debe configurarse para hacer NAT (Masquerade) del tráfico saliente.
```bash
# En el servidor Linux (ejecutar una vez o añadir a scripts de inicio):
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sysctl -w net.ipv4.ip_forward=1
```

**Configuración Cliente (`full_tunnel.toml`)**
```toml
[interface]
mode = "client"
vip = "10.0.0.2"
private_key = "KEY_CLIENT"

# Rutas Críticas:
# 1. "0.0.0.0/0": Captura TODO el tráfico de internet.
# 2. "8.8.8.8/32": Fuerza al DNS de Google a ir por el túnel (evita DNS Leak).
routes = ["0.0.0.0/0", "8.8.8.8/32"] 

[[peers]]
vip = "10.0.0.1"
endpoint = "SERVER_PUBLIC_IP:9000"
# AllowedIPs "0.0.0.0/0": El servidor está autorizado a enviarnos tráfico desde CUALQUIER lugar de internet.
allowed_ips = ["0.0.0.0/0"]
```

> **Nota sobre DNS:** Al activar este modo, es muy recomendable cambiar manualmente los DNS del cliente (en `/etc/resolv.conf` o configuración de red gráfica) a un servidor público (ej. `8.8.8.8` o `1.1.1.1`) para garantizar que las peticiones de nombres de dominio viajen protegidas por el túnel.

### 3.4. Escenario D: Site-to-Site (LAN Extension)

Este es el escenario más avanzado, posible gracias al nuevo motor de enrutamiento de Taltun v0.10. Permite unir dos redes locales completas (LANs) a través de internet de forma transparente.

**Casos de Uso Típicos:**
*   **Conexión Oficina-Nube:** Los servidores web en AWS (`10.0.0.x`) pueden imprimir facturas directamente en la impresora de red de la oficina física (`192.168.50.100`).
*   **Sucursales Interconectadas:** La sede de Madrid y la de Barcelona se ven entre sí.
*   **Acceso a IoT:** Monitorizar cámaras IP o PLCs industriales remotos sin exponerlos a internet.

**Topología:**
*   **Gateway Oficina:** IP LAN `192.168.50.5` (`eth0`). IP VPN `10.0.0.2` (`tun0`).
*   **Gateway Nube (Hub):** IP VPN `10.0.0.1`.
*   **Red Objetivo:** `192.168.50.0/24` (Ubicada físicamente detrás del Gateway Oficina).

**Requisito Previo en Gateway Oficina:**
Al actuar como Router entre la VPN y la LAN, debe tener activado el NAT y el Forwarding.

```bash
# 1. Habilitar Forwarding
sysctl -w net.ipv4.ip_forward=1

# 2. Configurar NAT (Masquerade)
# "Lo que salga por eth0 viniendo de la VPN, enmascáralo con la IP de la oficina"
# (Cambia 'eth0' por el nombre de tu interfaz física real)
iptables -t nat -A POSTROUTING -o eth0 -s 10.0.0.0/24 -j MASQUERADE

# 3. Permitir el paso de tráfico (Firewall)
iptables -A FORWARD -i tun0 -o eth0 -j ACCEPT
iptables -A FORWARD -i eth0 -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT
```

**Configuración Gateway Oficina (`office.toml`)**
```toml
[interface]
mode = "client"
vip = "10.0.0.2"
routes = ["10.0.0.0/24"] # Ruta para volver a la Nube

[[peers]]
vip = "10.0.0.1" # Gateway Nube
endpoint = "CLOUD_IP:9000"
allowed_ips = ["10.0.0.0/24"]
```

**Configuración Gateway Nube (`cloud.toml`)**
```toml
[interface]
mode = "server"
vip = "10.0.0.1"
# OS Routing: "Kernel, si llega algo para 192.168.50.x, tíralo al túnel"
routes = ["192.168.50.0/24"] 

[[peers]]
vip = "10.0.0.2"
# Engine Routing: "Motor Taltun, lo que sea para 192.168.50.x es para este peer"
allowed_ips = ["192.168.50.0/24"]
```
**3. Configuración de Red (NAT) en Gateway Oficina**
Para que los dispositivos de la oficina (impresoras, cámaras) sepan responder a las peticiones que vienen de la VPN sin cambiar su puerta de enlace por defecto, el Gateway debe enmascarar el tráfico (Source NAT).

```bash
# En el Gateway de la Oficina:
# "Todo lo que salga hacia la LAN (eth0) viniendo de la VPN (tun0), haz que parezca que viene de mi IP (192.168.50.5)"
iptables -t nat -A POSTROUTING -o eth0 -s 10.0.0.0/24 -j MASQUERADE
```

### 3.5. Escenario E: Client-to-Client Relay

En topologías tradicionales VPN, si dos clientes están detrás de routers NAT (ej. dos empleados trabajando desde sus respectivas casas), no pueden conectarse directamente entre sí. Taltun v0.10 soluciona esto utilizando el Servidor (Hub) como un switch de retransmisión inteligente.

**Casos de Uso Típicos:**
*   **Juegos en LAN Virtual:** Dos amigos en ciudades diferentes quieren jugar a un videojuego clásico (StarCraft, Quake) que solo soporta modo LAN. Se conectan al mismo servidor Taltun y se ven como si estuvieran en la misma habitación.
*   **VoIP P2P Segura:** Dos teléfonos IP o softphones en redes distintas establecen una llamada SIP cifrada. El tráfico de voz viaja de A al Hub y del Hub a B de forma transparente.
*   **Colaboración en Tiempo Real:** Un desarrollador (`10.0.0.2`) levanta un servidor web de pruebas en su portátil (`port 8080`) y quiere que su compañero de QA (`10.0.0.3`) lo revise inmediatamente, sin desplegar en staging.

**Funcionamiento Técnico (Hairpinning):**
1.  **Cliente A (`10.0.0.2`)** envía un paquete a **Cliente B (`10.0.0.3`)**.
2.  El paquete viaja cifrado hasta el **Servidor (`10.0.0.1`)**.
3.  El Servidor descifra la cabecera, ve que el destino es `10.0.0.3`.
4.  El motor de enrutamiento detecta que `10.0.0.3` es otro Peer conectado.
5.  **Relay:** El Servidor re-encripta el paquete con la clave de sesión de B y lo reenvía inmediatamente. El paquete nunca sale a la interfaz de red del Kernel del servidor (Zero-Copy Relay).

**Configuración:**
Es idéntica al **Escenario B (Road Warrior)**. No se requiere configuración especial de reenvío (`ip_forward`) ni reglas de firewall complejas en el servidor, ya que todo sucede dentro del espacio de usuario del proceso Taltun.

*   Ambos clientes deben tener la ruta hacia la subred VPN (`10.0.0.0/24`) en su `config.toml`.
*   El Servidor debe tener definidos a ambos peers en su configuración.

## 4. Puesta en Producción

Para entornos productivos, nunca se debe ejecutar Taltun manualmente en una terminal o sesión SSH. Se debe configurar como un servicio del sistema para garantizar que arranque automáticamente tras un reinicio y se recupere ante fallos.

### 4.1. Creación de Servicio systemd

Systemd es el estándar de gestión de servicios en Linux (Ubuntu, Debian, CentOS, RHEL).

**1. Instalar Binario y Configuración**
Movemos los archivos a ubicaciones estándar de Linux.

```bash
# Copiar el binario compilado
sudo cp bin/vpn /usr/local/bin/taltun
sudo chmod +x /usr/local/bin/taltun

# Crear directorio de configuración
sudo mkdir -p /etc/taltun
sudo cp config.toml /etc/taltun/config.toml
# Proteger la clave privada (solo root puede leer)
sudo chmod 600 /etc/taltun/config.toml
```

**2. Crear Archivo de Unidad**
Crea el archivo `/etc/systemd/system/taltun.service`:

```ini
[Unit]
Description=Taltun High-Performance VPN
Documentation=https://github.com/soyunomas/Taltun
# Esperar a que la red esté totalmente lista
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# Ejecutar como root es necesario para crear la interfaz TUN y modificar rutas
User=root
Group=root

# Comando de arranque
ExecStart=/usr/local/bin/taltun -config /etc/taltun/config.toml

# Reiniciar automáticamente si falla
Restart=always
RestartSec=3

# Aumentar límites de descriptores de archivo para alta concurrencia
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

**3. Activar el Servicio**

```bash
# Recargar systemd para leer el nuevo archivo
sudo systemctl daemon-reload

# Habilitar para que arranque al inicio del sistema
sudo systemctl enable taltun

# Arrancar inmediatamente
sudo systemctl start taltun

# Verificar estado
sudo systemctl status taltun
```

---

### 4.2. Monitorización de Logs y Debugging

Una vez el servicio está corriendo, la salida estándar se redirige al *journal* del sistema.

**Ver logs en tiempo real:**
```bash
sudo journalctl -u taltun -f
```

**Filtrar logs por errores:**
```bash
sudo journalctl -u taltun -p err
```

**Solución de Problemas Comunes:**

1.  **Error `Handshake Timeout` o `No response`:**
    *   Causa probable: Firewall bloqueando el puerto UDP 9000 o Clave Pública incorrecta en el Peer remoto.
    *   Solución: Verificar `ufw status` o Security Groups en AWS/Azure. Confirmar que la `public_key` derivada coincide.

2.  **Error `permission denied` al crear TUN:**
    *   Causa: El servicio no está corriendo como `root` o falta la capacidad `CAP_NET_ADMIN`.
    *   Solución: Asegurarse de que `User=root` está en el archivo systemd.

3.  **Bajo Rendimiento / Packet Loss:**
    *   Causa: Buffers UDP del Kernel saturados.
    *   Solución: Verificar que se aplicó el tuning de `sysctl` del Punto 1.3 (`net.core.rmem_max`).

4.  **Modo Debug:**
    *   Si necesitas ver cada paquete procesado para diagnosticar rutas, edita `/etc/taltun/config.toml` y establece `debug = true`, luego reinicia el servicio: `sudo systemctl restart taltun`.


