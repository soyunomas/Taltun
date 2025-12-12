# 🗺️ Hoja de Ruta Técnica (Technical Roadmap)

> **Estado Actual:** v0.10.0 (Routing V2 & Relay)
> **Objetivo:** Convertir el motor de alto rendimiento actual en una plataforma de conectividad universal.

---

## ✅ Fase 10: Internal Switching & Relay (COMPLETADA)
**Objetivo:** Permitir tráfico **Spoke-to-Spoke** (Cliente A -> Servidor -> Cliente B) y soporte de subredes (LAN access).

### 🔀 10.1. AllowedIPs & CIDR Lookup
- [x] **Subnet Routing:** Estructura `Router` (Radix Trie) para soportar listas de CIDRs (`192.168.1.0/24`) y no solo IPs (/32).
- [x] **LPM Trie:** Implementación de "Longest Prefix Match" en el *Hot Path* de TX para determinar a qué peer enviar un paquete.

### 📡 10.2. User-Space Relay (Hairpinning)
- [x] **Switching Logic:** En el ciclo de RX del Servidor, detección de destino hacia otro Peer.
- [x] **Zero-Copy Forwarding:** Re-encriptación y envío directo al canal de TX sin pasar por la interfaz TUN ni el Kernel.

---

## 📅 Fase 11: Conectividad Universal (v1.0.0)
**Objetivo:** Romper la barrera de NAT. Que funcione "desde cualquier lugar a cualquier lugar".

### 🌍 11.1. NAT Traversal (STUN Implementation)
- [ ] **STUN Client:** Implementación ligera (RFC 5389) para descubrir IP Pública y Puerto Mappeado al inicio.
- [ ] **Endpoint Updates:** Mecanismo para comunicar el endpoint reflexivo descubierto al peer remoto.

### 🥊 11.2. P2P Hole Punching
- [ ] **Signaling:** Intercambio de candidatos de conexión a través del servidor (Hub).
- [ ] **Punching Logic:** Envío de paquetes de "saludo" simultáneos para abrir puertos en NATs restrictivos.

---

## 📅 Fase 12: Multi-Platform Support (v1.1.0)
**Objetivo:** Salir de Linux.

### 🪟 12.1. Windows & macOS Support
- [x] **Driver Integration:** Completado en v0.9.0 mediante adopción de `wireguard/tun`.
- [ ] **Service Wrapper:** Implementar gestión de servicios de Windows (SCM) y LaunchD en macOS.
- [ ] **DNS Management:** Gestión de DNS en sistemas no-Linux.
