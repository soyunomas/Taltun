# Taltun Android

Cliente Android nativo para el protocolo Taltun v2. La aplicación usa `VpnService` para obtener la interfaz TUN del sistema y habla directamente con un peer Taltun mediante UDP, X25519, HKDF-SHA256 y ChaCha20-Poly1305.

## Compatibilidad

- Android 13 / API 33 o posterior.
- `compileSdk` / `targetSdk`: 36.
- Android Gradle Plugin 9.4.0 y Gradle 9.6.0.
- IPv4.
- Un peer principal configurado (servidor o Lighthouse). El relay funciona a través de ese peer. Los `PeerUpdate` de Lighthouse se ignoran en v0.1, por lo que el cliente Android permanece en relay en vez de promocionar P2P directo.

## Configuración

En la aplicación:

1. Genera una identidad X25519 y copia la clave pública.
2. Añade esa clave pública al `[[peers]]` del servidor/Lighthouse, junto con la VIP Android.
3. Introduce en Android la clave pública del servidor, su VIP y `host:puerto` público.
4. Define las rutas que Android enviará al túnel y los orígenes que el peer puede entregar (`AllowedIPs`).
5. Pulsa **Conectar** y acepta el diálogo VPN de Android.

Ejemplo en el servidor para un Android con VIP `10.0.0.2`:

```toml
[[peers]]
vip = "10.0.0.2"
public_key = "PUBLICA_QUE_MUESTRA_LA_APP"
```

Ejemplo en Android:

```text
VIP local:        10.0.0.2
VIP peer:         10.0.0.1
Endpoint:         vpn.example.com:9000
Routes:           10.0.0.0/24
Allowed sources:  10.0.0.0/24
MTU:              1380
```

Para full tunnel se puede usar `0.0.0.0/0`. El socket UDP exterior se excluye de la VPN mediante `VpnService.protect()`, evitando que el transporte Taltun se capture a sí mismo.

## Seguridad y protocolo

- Identidad X25519 estática fijada del peer.
- X25519 efímero nuevo por handshake.
- Transcript y mensajes de handshake autenticados con HMAC-SHA256.
- HKDF-SHA256 produce claves separadas por dirección y clave de confirmación.
- Datos protegidos con ChaCha20-Poly1305 y la cabecera Taltun como AAD.
- Contador y ventana anti-replay por sesión.
- Ventana de 30 s para la generación anterior.
- Keepalive de 10 s.
- El `Finish` se retransmite hasta confirmación mediante tráfico autenticado del responder.
- El peer Go puede iniciar el rekey; Android actúa como responder y cambia de generación tras validar el `Finish`.

La clave privada se guarda en `SharedPreferences` privados de la aplicación y `allowBackup=false`. Para un despliegue con requisitos de secreto más estrictos, la siguiente evolución debería envolver la configuración sensible con una clave AES del Android Keystore.

## Build

El workflow `Android` compila y ejecuta los tests con JDK 17, Gradle 9.6.0 y el SDK Android 36, y publica `app-debug.apk` como artifact `taltun-android-apk`.

Desde un entorno Android configurado:

```bash
cd android
gradle :app:testDebugUnitTest :app:assembleDebug
```

El APK queda en:

```text
android/app/build/outputs/apk/debug/app-debug.apk
```
