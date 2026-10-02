package com.soyunomas.taltun.android

import java.util.concurrent.atomic.AtomicLong

object VpnRuntimeState {
    enum class Status { DISCONNECTED, CONNECTING, CONNECTED, ERROR }

    @Volatile var status: Status = Status.DISCONNECTED
    @Volatile var detail: String = "Desconectado"
    @Volatile var activeProfileId: String? = null
    @Volatile var activeProfileName: String? = null
    val txBytes = AtomicLong(0)
    val rxBytes = AtomicLong(0)
    val udpTxPackets = AtomicLong(0)
    val udpRxPackets = AtomicLong(0)
    val handshakeTx = AtomicLong(0)
    val handshakeRx = AtomicLong(0)
    val tunDroppedPackets = AtomicLong(0)
    @Volatile var udpLocal: String = "—"
    @Volatile var udpRemote: String = "—"
    @Volatile var underlyingNetwork: String = "—"

    fun resetCounters() {
        txBytes.set(0)
        rxBytes.set(0)
        udpTxPackets.set(0)
        udpRxPackets.set(0)
        handshakeTx.set(0)
        handshakeRx.set(0)
        tunDroppedPackets.set(0)
        udpLocal = "—"
        udpRemote = "—"
        underlyingNetwork = "—"
    }
}
