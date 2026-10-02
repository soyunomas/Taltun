# Taltun Android — TODO de implementación

## Fase 1 — Proyecto y plataforma
- [x] Crear proyecto Android dentro de `android/`.
- [x] Fijar `minSdk 33`, `targetSdk 36`, AGP 9.4.0 y Java 17.
- [x] Declarar `VpnService`, permisos y foreground service compatible con Android moderno.

## Fase 2 — Protocolo Taltun v2
- [x] X25519 estático y efímero.
- [x] Transcript HMAC-SHA256 compatible con Go.
- [x] HKDF-SHA256 con claves direccionales.
- [x] ChaCha20-Poly1305 con cabecera como AAD.
- [x] Codificación/parseo de handshake, finish, cookie y data header.
- [x] Ventana anti-replay de 2048 paquetes.

## Fase 3 — Ciclo de sesión
- [x] Handshake iniciador y respondedor.
- [x] Cookies anti-DoS recibidas del endpoint configurado.
- [x] Keepalive de 10 s.
- [x] Generación anterior con gracia de 30 s.
- [x] Aceptar rekey iniciado por el servidor Go.
- [x] Retransmitir `HandshakeFinish` hasta confirmación autenticada.
- [x] Resolver colisión de handshake inicial de forma determinista.

## Fase 4 — Dataplane Android
- [x] Crear TUN con `VpnService.Builder`.
- [x] Leer TUN → cifrar → UDP.
- [x] UDP → autenticar/descifrar → validar source ACL → TUN.
- [x] Excluir el socket UDP del túnel con `VpnService.protect()`.
- [x] Soportar rutas split y full tunnel.
- [x] Endpoint IPv4 por IP o hostname.

## Fase 5 — Aplicación y configuración
- [x] Pantalla nativa de configuración.
- [x] Generación de identidad X25519.
- [x] Copia de clave pública para configurar el servidor.
- [x] Persistencia local del perfil.
- [x] Conectar/desconectar con consentimiento de Android.
- [x] Estado y contadores TX/RX.
- [x] Notificación foreground con acción de desconexión.

## Fase 6 — Verificación y entrega
- [x] Vectores criptográficos contrastados con la implementación Go de Taltun.
- [x] Test de handshake completo y transporte cifrado.
- [x] Test de replay/reordenamiento.
- [x] Test de pérdida del primer `Finish` y recuperación.
- [x] Test de rekey iniciado por el peer.
- [x] Compilar tests Android en GitHub Actions.
- [x] Generar APK instalable y publicarlo como artifact.

## Fuera del alcance de v0.1

- P2P directo a partir de `PeerUpdate` de Lighthouse; v0.1 mantiene conectividad por relay.
- Múltiples peers configurables desde UI.
- Almacenamiento de la clave privada envuelto con Android Keystore.
