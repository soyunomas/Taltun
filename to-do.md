# 🗺️ Hoja de Ruta Técnica (Technical Roadmap)

> **Estado Actual:** v0.8.0 (Usability & Automation)
> **Objetivo:** Convertir el motor de alto rendimiento actual en una plataforma de conectividad universal, segura y resistente.

---

## 📅 Fase 8: Usabilidad y Gestión de Estado (v0.8.0)
**Objetivo:** Eliminar la configuración manual de interfaces y flags kilométricos. "Battery-included experience".

### 🔧 8.1. Configuración Estructurada (Configuration Management)
- [x] **Soporte TOML:** Implementado con `go-toml/v2` para configuración estructurada y tipada sin reflection overhead.
- [x] **Hot-Reloading (Parcial):** Prioridad de flags sobre archivo para cambios rápidos.

### 🐧 8.2. Linux Netlink Automation
- [x] **Programación Automática de IP:**
    - Taltun ahora configura automáticamente IP, Máscara (/24), MTU y estado UP de la interfaz TUN al arrancar.
    - Implementado usando `vishvananda/netlink`.
- [x] **Gestión de Rutas del Kernel:**
    - Capacidad de añadir rutas extra en la tabla del sistema operativo (`ip route add`) para redirigir tráfico de subredes específicas.

### 🧹 8.3. Graceful Shutdown & Cleanup
- [x] **Context Cancellation:** Propagación de `context.Context` desde `main`.
- [x] **Resource Teardown:** Cierre limpio de descriptores de archivo TUN/UDP al recibir `SIGINT`/`SIGTERM`.

---

## 📅 Fase 9: Hardening de Seguridad (v0.9.0)
**Objetivo:** Elevar la seguridad criptográfica a estándares industriales (auditable).

### 🔄 9.1. Rekeying Automático (Rotación de Claves)
*El problema: Actualmente la clave de sesión dura para siempre hasta reiniciar.*
- [ ] **Time-based Rekey:** Iniciar nuevo handshake ECDH cada 120 segundos.
- [ ] **Volume-based Rekey:** Iniciar nuevo handshake tras transmitir $2^{64}$ paquetes o 1GB de datos.
- [ ] **Mecanismo:** El `Initiator` envía un paquete de handshake especial. El tráfico de datos se pausa brevemente (buffer) o se usa la clave vieja hasta confirmar la nueva (Overlap window).

### 🛡️ 9.2. Anti-Replay Protection (Ventana Deslizante)
*El problema: Un atacante podría capturar un paquete UDP válido y reenviarlo para consumir recursos.*
- [ ] **Implementación de Bitmap:**
    - Usar una ventana deslizante de 2048 bits (array de `uint64`).
    - **Lógica:** Si `counter < min_window`, descartar. Si `counter` ya está marcado en el bitmap, descartar.
    - **Optimización:** Operaciones bitwise (`1 << n`) son O(1).

### 💓 9.3. Keepalives & Dead Peer Detection (DPD)
- [ ] **Heartbeats:** Enviar un paquete vacío cifrado cada 10s si no hay tráfico de datos.
    - **Objetivo:** Mantener abiertos los mapeos NAT en routers intermedios.
- [ ] **Handshake Timeout:** Si no hay respuesta a un handshake en 5s, marcar peer como `Offline` y limpiar estado de sesión.

---

## 📅 Fase 10: Conectividad Universal (v1.0.0)
**Objetivo:** Romper la barrera de NAT. Que funcione "desde cualquier lugar a cualquier lugar".

### 🌍 10.1. NAT Traversal (STUN / Hole Punching)
- [ ] **Implementación STUN Simple:**
    - El cliente envía petición a un servidor STUN público (o propio) para descubrir su `IP_Publica:Puerto` real.
- [ ] **UDP Hole Punching:**
    - Coordinación entre dos peers (A y B) para enviarse paquetes UDP simultáneamente y "engañar" a sus firewalls para que abran el puerto.
    - Requiere un servidor de coordinación ligero (Signaling Server).

### 🔄 10.2. Relayed Connections (Fallback)
*Si el P2P directo falla (Symmetric NATs), usar un relay.*
- [ ] **Modo Relay (DERP):**
    - Implementar un servidor intermedio simple que reenvíe paquetes cifrados ciegamente (`io.Copy`) cuando la conexión directa no es posible.
    - Prioridad: Directo > UDP Hole Punch > Relay TCP/UDP.

---

## 📅 Fase 11: Multi-Platform Support (v1.1.0)
**Objetivo:** Salir de Linux.

### 🪟 11.1. Windows Support (Wintun)
- [ ] **Wintun Driver Integration:**
    - Usar `WireGuard/wintun` (driver de alto rendimiento firmado por Microsoft).
    - Implementar adaptador en Go usando `golang.org/x/sys/windows`.
    - Manejar IPC mediante Named Pipes en lugar de sockets Unix.

### 🍎 11.2. macOS & BSD
- [ ] **Utun Interface:**
    - Implementar soporte para dispositivos `utun` nativos de BSD.
    - Configuración de red mediante llamadas `ioctl` o binarios del sistema (`ifconfig`/`route` como fallback).
