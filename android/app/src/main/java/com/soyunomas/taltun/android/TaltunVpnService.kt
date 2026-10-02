package com.soyunomas.taltun.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import com.soyunomas.taltun.android.config.ConfigStore
import com.soyunomas.taltun.android.config.TaltunConfig
import com.soyunomas.taltun.android.core.Ipv4
import com.soyunomas.taltun.android.core.TaltunProtocol
import com.soyunomas.taltun.android.core.TaltunSession
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

class TaltunVpnService : VpnService() {
    companion object {
        const val ACTION_CONNECT = "com.soyunomas.taltun.android.CONNECT"
        const val ACTION_DISCONNECT = "com.soyunomas.taltun.android.DISCONNECT"
        private const val NOTIFICATION_ID = 1001
        private const val CHANNEL_ID = "taltun_vpn"
    }

    private val running = AtomicBoolean(false)
    private var vpnInterface: ParcelFileDescriptor? = null
    private var socket: DatagramSocket? = null
    private var workers = Executors.newFixedThreadPool(2)
    private var scheduler: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor()
    private val remoteEndpoint = AtomicReference<InetSocketAddress>()
    @Volatile private var session: TaltunSession? = null
    @Volatile private var config: TaltunConfig? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_DISCONNECT -> {
                stopTunnel("Desconectado")
                stopSelf()
            }
            ACTION_CONNECT, null -> {
                // A service started with startForegroundService() must promote itself
                // immediately, before DNS, TUN creation or any other potentially slow I/O.
                startAsForeground("Taltun", "Preparando túnel…")
                if (running.compareAndSet(false, true)) {
                    VpnRuntimeState.resetCounters()
                    setState(VpnRuntimeState.Status.CONNECTING, "Preparando túnel")
                    Thread({ startTunnel() }, "taltun-start").start()
                }
            }
        }
        return Service.START_NOT_STICKY
    }

    override fun onRevoke() { stopTunnel("Permiso VPN revocado"); stopSelf(); super.onRevoke() }
    override fun onDestroy() { stopTunnel("Desconectado"); super.onDestroy() }

    private fun startTunnel() {
        try {
            val loaded = ConfigStore(this).load()
            val errors = loaded.validate()
            require(errors.isEmpty()) { errors.joinToString(". ") }
            config = loaded
            val endpoint = loaded.endpointParts()
            val resolvedEndpoint = InetSocketAddress(Ipv4.resolveV4(endpoint.host), endpoint.port)
            remoteEndpoint.set(resolvedEndpoint)

            val underlyingNetwork = findUnderlyingNetwork()
                ?: error("No se encontró una red física disponible para transportar Taltun")
            VpnRuntimeState.underlyingNetwork = describeNetwork(underlyingNetwork)

            val localSession = TaltunSession(loaded.localVipInt(), loaded.privateKey(), loaded.peerVipInt(), loaded.peerPublicKey())
            session = localSession

            val descriptor = establishVpn(loaded, underlyingNetwork)
            vpnInterface = descriptor

            val udp = DatagramSocket(null).apply {
                reuseAddress = false
                bind(InetSocketAddress(0))
                soTimeout = 1_000
            }
            check(protect(udp)) { "Android no pudo proteger el socket UDP del túnel" }
            underlyingNetwork.bindSocket(udp)
            check(setUnderlyingNetworks(arrayOf(underlyingNetwork))) {
                "Android no pudo registrar la red física subyacente"
            }
            socket = udp

            VpnRuntimeState.udpLocal = udp.localSocketAddress?.toString() ?: "desconocido"
            VpnRuntimeState.udpRemote = resolvedEndpoint.address.hostAddress + ":" + resolvedEndpoint.port

            updateForegroundNotification(loaded.profileName, "Negociando sesión v2")
            setState(VpnRuntimeState.Status.CONNECTING, "Preparando primer handshake")

            sendHandshakePacket(udp, localSession.createHandshakeInit(System.currentTimeMillis()))

            workers.execute { udpReceiveLoop(udp, descriptor) }
            workers.execute { tunReadLoop(udp, descriptor) }
            scheduler.scheduleAtFixedRate({ maintenanceTick(udp) }, 250, 250, TimeUnit.MILLISECONDS)
        } catch (error: Throwable) {
            setState(VpnRuntimeState.Status.ERROR, error.message ?: error.javaClass.simpleName)
            stopTunnel(null); stopSelf()
        }
    }

    private fun establishVpn(cfg: TaltunConfig, underlyingNetwork: Network): ParcelFileDescriptor {
        val builder = Builder()
            .setSession(cfg.profileName)
            .setMtu(cfg.mtu)
            .addAddress(cfg.localVip, 32)
            .setBlocking(true)
            .setUnderlyingNetworks(arrayOf(underlyingNetwork))
        cfg.routes.forEach { route ->
            val prefix = Ipv4.parsePrefix(route)
            builder.addRoute(Ipv4.format(prefix.network), prefix.prefixLength)
        }
        cfg.dnsServers.forEach(builder::addDnsServer)
        return builder.establish() ?: error("Android rechazó la creación de la interfaz VPN")
    }

    private fun findUnderlyingNetwork(): Network? {
        val connectivity = getSystemService(ConnectivityManager::class.java)

        fun usable(network: Network): Boolean {
            val caps = connectivity.getNetworkCapabilities(network) ?: return false
            return !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
        }

        connectivity.allNetworks.firstOrNull { network ->
            val caps = connectivity.getNetworkCapabilities(network)
            caps != null &&
                usable(network) &&
                caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
        }?.let { return it }

        connectivity.activeNetwork?.let { if (usable(it)) return it }
        return connectivity.allNetworks.firstOrNull(::usable)
    }

    private fun describeNetwork(network: Network): String {
        val connectivity = getSystemService(ConnectivityManager::class.java)
        val caps = connectivity.getNetworkCapabilities(network)
        return when {
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true -> "Wi-Fi"
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true -> "móvil"
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) == true -> "Ethernet"
            else -> network.toString()
        }
    }

    private fun tunReadLoop(udp: DatagramSocket, descriptor: ParcelFileDescriptor) {
        val cfg = config ?: return
        val input = FileInputStream(descriptor.fileDescriptor)
        val buffer = ByteArray(maxOf(4096, cfg.mtu + 128))
        try {
            while (running.get()) {
                val count = input.read(buffer)
                if (count <= 0) continue

                // Taltun v2 is IPv4-only. Android can still surface non-IPv4
                // traffic through the TUN; do not send it to the Go peer.
                if (count < 20 || ((buffer[0].toInt() ushr 4) and 0x0f) != 4) {
                    VpnRuntimeState.tunDroppedPackets.incrementAndGet()
                    continue
                }
                val ihl = (buffer[0].toInt() and 0x0f) * 4
                if (ihl < 20 || count < ihl) {
                    VpnRuntimeState.tunDroppedPackets.incrementAndGet()
                    continue
                }

                val plaintext = buffer.copyOf(count)
                val source = Ipv4.fromPacket(plaintext, source = true)
                if (source == null || source != cfg.localVipInt()) {
                    VpnRuntimeState.tunDroppedPackets.incrementAndGet()
                    continue
                }

                val encrypted = session?.seal(plaintext, System.currentTimeMillis()) ?: continue
                sendUdp(udp, encrypted)
                VpnRuntimeState.txBytes.addAndGet(count.toLong())
            }
        } catch (error: Throwable) { if (running.get()) fail("Lectura TUN: ${error.message}") }
    }

    private fun udpReceiveLoop(udp: DatagramSocket, descriptor: ParcelFileDescriptor) {
        val output = FileOutputStream(descriptor.fileDescriptor); val receiveBuffer = ByteArray(4096)
        try {
            while (running.get()) {
                val datagram = DatagramPacket(receiveBuffer, receiveBuffer.size)
                try { udp.receive(datagram) } catch (_: SocketTimeoutException) { continue }
                val source = datagram.socketAddress as? InetSocketAddress ?: continue
                VpnRuntimeState.udpRxPackets.incrementAndGet()
                val bytes = datagram.data.copyOfRange(datagram.offset, datagram.offset + datagram.length)
                processUdpPacket(udp, output, source, bytes)
            }
        } catch (error: Throwable) { if (running.get()) fail("Recepción UDP: ${error.message}") }
    }

    private fun processUdpPacket(udp: DatagramSocket, tunOutput: FileOutputStream, source: InetSocketAddress, packet: ByteArray) {
        if (packet.isEmpty()) return
        val now = System.currentTimeMillis(); val localSession = session ?: return
        when (packet[0]) {
            TaltunProtocol.MSG_HANDSHAKE_INIT, TaltunProtocol.MSG_HANDSHAKE_RESP -> {
                VpnRuntimeState.handshakeRx.incrementAndGet()
                val handshake = TaltunProtocol.parseHandshake(packet) ?: return
                val response = if (handshake.type == TaltunProtocol.MSG_HANDSHAKE_INIT) localSession.handleHandshakeInit(handshake, now) else localSession.handleHandshakeResponse(handshake, now)
                if (response != null) { remoteEndpoint.set(source); sendUdp(udp, response, source) }
                updateConnectedState(localSession)
            }
            TaltunProtocol.MSG_HANDSHAKE_FINISH -> {
                VpnRuntimeState.handshakeRx.incrementAndGet()
                val finish = TaltunProtocol.parseHandshakeFinish(packet) ?: return
                if (localSession.handleHandshakeFinish(finish, now)) {
                    remoteEndpoint.set(source); localSession.seal(ByteArray(0), now)?.let { sendUdp(udp, it, source) }; updateConnectedState(localSession)
                }
            }
            TaltunProtocol.MSG_COOKIE_REPLY -> {
                VpnRuntimeState.handshakeRx.incrementAndGet()
                if (!sameEndpoint(source, remoteEndpoint.get())) return
                val cookie = TaltunProtocol.parseCookieReply(packet) ?: return; localSession.setCookie(cookie)
                if (localSession.needsInitiatorHandshake(now)) sendHandshakePacket(udp, localSession.createHandshakeInit(now))
            }
            TaltunProtocol.MSG_DATA -> {
                val data = TaltunProtocol.parseData(packet) ?: return; val plaintext = localSession.open(data, now) ?: return
                remoteEndpoint.set(source); updateConnectedState(localSession)
                if (plaintext.isEmpty() || !isAllowedSource(plaintext)) return
                tunOutput.write(plaintext); VpnRuntimeState.rxBytes.addAndGet(plaintext.size.toLong())
            }
            TaltunProtocol.MSG_PEER_UPDATE -> Unit
        }
    }

    private fun maintenanceTick(udp: DatagramSocket) {
        if (!running.get()) return
        try {
            val localSession = session ?: return; val now = System.currentTimeMillis()
            localSession.finishRetransmission(now)?.let { sendHandshakePacket(udp, it) }
            if (localSession.needsInitiatorHandshake(now)) { sendHandshakePacket(udp, localSession.createHandshakeInit(now)) }
            else if (localSession.needsKeepalive(now)) { localSession.seal(ByteArray(0), now)?.let { sendUdp(udp, it) } }
            updateConnectedState(localSession)
        } catch (error: Throwable) { if (running.get()) fail("Mantenimiento: ${error.message}") }
    }

    private fun isAllowedSource(packet: ByteArray): Boolean {
        val source = Ipv4.fromPacket(packet, source = true) ?: return false; val cfg = config ?: return false
        return cfg.sourcePrefixes().any { it.contains(source) }
    }

    private fun sendUdp(udp: DatagramSocket, data: ByteArray, destination: InetSocketAddress? = remoteEndpoint.get()) {
        val endpoint = destination ?: error("Endpoint UDP no configurado")
        udp.send(DatagramPacket(data, data.size, endpoint))
        VpnRuntimeState.udpTxPackets.incrementAndGet()
    }

    private fun sendHandshakePacket(
        udp: DatagramSocket,
        data: ByteArray,
        destination: InetSocketAddress? = remoteEndpoint.get(),
    ) {
        sendUdp(udp, data, destination)
        val attempt = VpnRuntimeState.handshakeTx.incrementAndGet()
        val target = destination ?: remoteEndpoint.get()
        val targetText = target?.let {
            (it.address?.hostAddress ?: it.hostString) + ":" + it.port
        } ?: "?"
        setState(
            VpnRuntimeState.Status.CONNECTING,
            "Handshake TX #" + attempt +
                " · " + VpnRuntimeState.underlyingNetwork +
                " · " + VpnRuntimeState.udpLocal +
                " → " + targetText +
                " · RX UDP " + VpnRuntimeState.udpRxPackets.get(),
        )
    }

    private fun sameEndpoint(a: InetSocketAddress?, b: InetSocketAddress?): Boolean =
        a != null && b != null && a.port == b.port && a.address == b.address

    private fun updateConnectedState(localSession: TaltunSession) {
        if (localSession.hasSession()) setState(VpnRuntimeState.Status.CONNECTED, "Conectado · sesión ${java.lang.Long.toUnsignedString(localSession.currentSessionId(), 16)}")
    }

    private fun buildNotification(profileName: String, message: String): Notification {
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(NotificationChannel(CHANNEL_ID, "Taltun VPN", NotificationManager.IMPORTANCE_LOW))
        val pendingDisconnect = PendingIntent.getService(this, 2, Intent(this, TaltunVpnService::class.java).setAction(ACTION_DISCONNECT), PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val openApp = PendingIntent.getActivity(this, 1, Intent(this, MainActivity::class.java), PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        return Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_taltun)
            .setContentTitle("Taltun · $profileName")
            .setContentText(message)
            .setContentIntent(openApp)
            .setOngoing(true)
            .addAction(Notification.Action.Builder(null, "Desconectar", pendingDisconnect).build())
            .build()
    }

    private fun startAsForeground(profileName: String, message: String) {
        val notification = buildNotification(profileName, message)
        if (Build.VERSION.SDK_INT >= 34) {
            try { startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED) }
            catch (_: SecurityException) { startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE) }
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun updateForegroundNotification(profileName: String, message: String) {
        getSystemService(NotificationManager::class.java)
            .notify(NOTIFICATION_ID, buildNotification(profileName, message))
    }

    private fun fail(message: String) { setState(VpnRuntimeState.Status.ERROR, message); stopTunnel(null); stopSelf() }

    @Synchronized
    private fun stopTunnel(finalDetail: String?) {
        if (!running.getAndSet(false) && vpnInterface == null && socket == null) {
            if (finalDetail != null) setState(VpnRuntimeState.Status.DISCONNECTED, finalDetail); return
        }
        runCatching { scheduler.shutdownNow() }; runCatching { workers.shutdownNow() }; runCatching { socket?.close() }; runCatching { vpnInterface?.close() }
        socket = null; vpnInterface = null; session = null; config = null; remoteEndpoint.set(null)
        VpnRuntimeState.udpLocal = "—"; VpnRuntimeState.udpRemote = "—"; VpnRuntimeState.underlyingNetwork = "—"
        scheduler = Executors.newSingleThreadScheduledExecutor(); workers = Executors.newFixedThreadPool(2)
        stopForeground(STOP_FOREGROUND_REMOVE)
        if (finalDetail != null) setState(VpnRuntimeState.Status.DISCONNECTED, finalDetail)
    }

    private fun setState(status: VpnRuntimeState.Status, detail: String) { VpnRuntimeState.status = status; VpnRuntimeState.detail = detail }
}
