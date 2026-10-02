package com.soyunomas.taltun.android

import java.util.concurrent.atomic.AtomicLong

object VpnRuntimeState {
    enum class Status { DISCONNECTED, CONNECTING, CONNECTED, ERROR }

    @Volatile var status: Status = Status.DISCONNECTED
    @Volatile var detail: String = "Desconectado"
    val txBytes = AtomicLong(0)
    val rxBytes = AtomicLong(0)

    fun resetCounters() {
        txBytes.set(0)
        rxBytes.set(0)
    }
}
