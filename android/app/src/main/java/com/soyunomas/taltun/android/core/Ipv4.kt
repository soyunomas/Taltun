package com.soyunomas.taltun.android.core

import java.net.Inet4Address
import java.net.InetAddress

object Ipv4 {
    data class Prefix(val network: Int, val prefixLength: Int) {
        private val mask: Int = when (prefixLength) {
            0 -> 0
            else -> (-1 shl (32 - prefixLength))
        }
        fun contains(address: Int): Boolean = (address and mask) == network
    }

    fun parse(value: String): Int {
        val parts = value.trim().split('.')
        require(parts.size == 4) { "invalid IPv4 address: $value" }
        var result = 0
        for (part in parts) {
            val octet = part.toIntOrNull() ?: throw IllegalArgumentException("invalid IPv4 address: $value")
            require(octet in 0..255) { "invalid IPv4 address: $value" }
            result = (result shl 8) or octet
        }
        return result
    }

    fun format(value: Int): String = listOf(
        value ushr 24 and 0xff, value ushr 16 and 0xff, value ushr 8 and 0xff, value and 0xff
    ).joinToString(".")

    fun parsePrefix(value: String): Prefix {
        val parts = value.trim().split('/')
        require(parts.size == 2) { "invalid IPv4 CIDR: $value" }
        val ip = parse(parts[0])
        val prefixLength = parts[1].toIntOrNull() ?: throw IllegalArgumentException("invalid IPv4 CIDR: $value")
        require(prefixLength in 0..32) { "invalid IPv4 CIDR: $value" }
        val mask = if (prefixLength == 0) 0 else -1 shl (32 - prefixLength)
        return Prefix(ip and mask, prefixLength)
    }

    fun fromPacket(packet: ByteArray, source: Boolean): Int? {
        if (packet.size < 20 || ((packet[0].toInt() ushr 4) and 0x0f) != 4) return null
        val ihl = (packet[0].toInt() and 0x0f) * 4
        if (ihl < 20 || packet.size < ihl) return null
        val offset = if (source) 12 else 16
        return ((packet[offset].toInt() and 0xff) shl 24) or
            ((packet[offset + 1].toInt() and 0xff) shl 16) or
            ((packet[offset + 2].toInt() and 0xff) shl 8) or
            (packet[offset + 3].toInt() and 0xff)
    }

    fun resolveV4(host: String): Inet4Address = InetAddress.getAllByName(host)
        .firstOrNull { it is Inet4Address } as? Inet4Address
        ?: throw IllegalArgumentException("hostname has no IPv4 address: $host")
}
