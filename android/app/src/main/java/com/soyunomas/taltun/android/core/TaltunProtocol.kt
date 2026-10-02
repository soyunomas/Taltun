package com.soyunomas.taltun.android.core

import java.nio.ByteBuffer
import java.nio.ByteOrder

object TaltunProtocol {
    const val MSG_HANDSHAKE_INIT: Byte = 0x01
    const val MSG_HANDSHAKE_RESP: Byte = 0x02
    const val MSG_DATA: Byte = 0x03
    const val MSG_COOKIE_REPLY: Byte = 0x04
    const val MSG_HANDSHAKE_FINISH: Byte = 0x05
    const val MSG_PEER_UPDATE: Byte = 0x06

    const val HEADER_SIZE = 25
    const val NONCE_SIZE = 12
    const val AUTH_TAG_SIZE = 32
    const val COOKIE_SIZE = 16
    const val HANDSHAKE_SIZE = 109
    const val HANDSHAKE_FINISH_SIZE = 45

    data class DataHeader(val senderVip: Int, val sessionId: Long, val nonce: ByteArray, val ciphertext: ByteArray, val aad: ByteArray)
    data class Handshake(val type: Byte, val senderVip: Int, val sessionId: Long, val staticPublic: ByteArray, val ephemeralPublic: ByteArray, val authTag: ByteArray, val cookie: ByteArray?)
    data class HandshakeFinish(val senderVip: Int, val sessionId: Long, val authTag: ByteArray)

    fun encodeDataHeader(senderVip: Int, sessionId: Long, nonce: ByteArray): ByteArray {
        require(sessionId != 0L)
        require(nonce.size == NONCE_SIZE)
        return ByteBuffer.allocate(HEADER_SIZE).order(ByteOrder.BIG_ENDIAN)
            .put(MSG_DATA).putInt(senderVip).putLong(sessionId).put(nonce).array()
    }

    fun parseData(packet: ByteArray, length: Int = packet.size): DataHeader? {
        if (length < HEADER_SIZE || packet[0] != MSG_DATA) return null
        val header = packet.copyOfRange(0, HEADER_SIZE)
        val buffer = ByteBuffer.wrap(header).order(ByteOrder.BIG_ENDIAN)
        buffer.get()
        val senderVip = buffer.int
        val sessionId = buffer.long
        if (sessionId == 0L) return null
        val nonce = ByteArray(NONCE_SIZE).also(buffer::get)
        return DataHeader(senderVip, sessionId, nonce, packet.copyOfRange(HEADER_SIZE, length), header)
    }

    fun encodeHandshake(type: Byte, senderVip: Int, sessionId: Long, staticPublic: ByteArray, ephemeralPublic: ByteArray, authTag: ByteArray, cookie: ByteArray? = null): ByteArray {
        require(type == MSG_HANDSHAKE_INIT || type == MSG_HANDSHAKE_RESP)
        require(sessionId != 0L)
        require(staticPublic.size == 32 && ephemeralPublic.size == 32)
        require(authTag.size == AUTH_TAG_SIZE)
        require(cookie == null || cookie.size == COOKIE_SIZE)
        val out = ByteBuffer.allocate(HANDSHAKE_SIZE + (cookie?.size ?: 0)).order(ByteOrder.BIG_ENDIAN)
        out.put(type).putInt(senderVip).putLong(sessionId).put(staticPublic).put(ephemeralPublic).put(authTag)
        if (cookie != null) out.put(cookie)
        return out.array()
    }

    fun parseHandshake(packet: ByteArray, length: Int = packet.size): Handshake? {
        if (length != HANDSHAKE_SIZE && length != HANDSHAKE_SIZE + COOKIE_SIZE) return null
        val buffer = ByteBuffer.wrap(packet, 0, length).order(ByteOrder.BIG_ENDIAN)
        val type = buffer.get()
        if (type != MSG_HANDSHAKE_INIT && type != MSG_HANDSHAKE_RESP) return null
        val senderVip = buffer.int
        val sessionId = buffer.long
        if (sessionId == 0L) return null
        val staticPublic = ByteArray(32).also(buffer::get)
        val ephemeralPublic = ByteArray(32).also(buffer::get)
        val authTag = ByteArray(AUTH_TAG_SIZE).also(buffer::get)
        val cookie = if (length == HANDSHAKE_SIZE + COOKIE_SIZE) ByteArray(COOKIE_SIZE).also(buffer::get) else null
        return Handshake(type, senderVip, sessionId, staticPublic, ephemeralPublic, authTag, cookie)
    }

    fun encodeHandshakeFinish(senderVip: Int, sessionId: Long, authTag: ByteArray): ByteArray {
        require(sessionId != 0L)
        require(authTag.size == AUTH_TAG_SIZE)
        return ByteBuffer.allocate(HANDSHAKE_FINISH_SIZE).order(ByteOrder.BIG_ENDIAN)
            .put(MSG_HANDSHAKE_FINISH).putInt(senderVip).putLong(sessionId).put(authTag).array()
    }

    fun parseHandshakeFinish(packet: ByteArray, length: Int = packet.size): HandshakeFinish? {
        if (length != HANDSHAKE_FINISH_SIZE || packet[0] != MSG_HANDSHAKE_FINISH) return null
        val buffer = ByteBuffer.wrap(packet, 0, length).order(ByteOrder.BIG_ENDIAN)
        buffer.get()
        val senderVip = buffer.int
        val sessionId = buffer.long
        if (sessionId == 0L) return null
        return HandshakeFinish(senderVip, sessionId, ByteArray(AUTH_TAG_SIZE).also(buffer::get))
    }

    fun parseCookieReply(packet: ByteArray, length: Int = packet.size): ByteArray? {
        if (length != 1 + COOKIE_SIZE || packet[0] != MSG_COOKIE_REPLY) return null
        return packet.copyOfRange(1, 1 + COOKIE_SIZE)
    }

    fun nonce(counter: Long): ByteArray = ByteBuffer.allocate(NONCE_SIZE).order(ByteOrder.BIG_ENDIAN).putInt(0).putLong(counter).array()
    fun nonceCounter(nonce: ByteArray): Long = ByteBuffer.wrap(nonce, 4, 8).order(ByteOrder.BIG_ENDIAN).long
}
