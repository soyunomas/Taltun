package com.soyunomas.taltun.android.core

import java.util.concurrent.atomic.AtomicLong

class TaltunSession(
    private val localVip: Int,
    private val staticPrivate: ByteArray,
    private val peerVip: Int,
    private val peerStaticPublic: ByteArray,
) {
    companion object {
        const val HANDSHAKE_RETRY_MS = 2_000L
        const val KEEPALIVE_MS = 10_000L
        // The Go peer sends keepalives every ~10 s. If we receive nothing
        // authenticated for two keepalive intervals, assume the peer lost
        // its session state (for example after a server restart) and rekey.
        const val SESSION_STALE_MS = 20_000L
        const val PREVIOUS_GRACE_MS = 30_000L
        const val FINISH_MAX_RETRIES = 5
    }

    private data class TrafficSession(
        val id: Long,
        val txKey: ByteArray,
        val rxKey: ByteArray,
        val createdAt: Long,
        var expiresAt: Long = Long.MAX_VALUE,
        val txCounter: AtomicLong = AtomicLong(0),
        val replay: ReplayWindow = ReplayWindow(),
    )

    private data class PendingInitiator(
        val sessionId: Long,
        val ephemeral: TaltunCrypto.RawKeyPair,
        val packet: ByteArray,
        val createdAt: Long,
    )

    private data class PendingResponder(
        val sessionId: Long,
        val initiatorEphemeral: ByteArray,
        val responderEphemeral: TaltunCrypto.RawKeyPair,
        val keys: TaltunCrypto.SessionKeys,
        val responsePacket: ByteArray,
    )

    private data class AwaitingFinishAck(
        val sessionId: Long,
        val packet: ByteArray,
        var attempts: Int,
        var lastSentAt: Long,
    )

    private val localStaticPublic = TaltunCrypto.publicFromPrivate(staticPrivate)
    private val staticShared = TaltunCrypto.sharedSecret(staticPrivate, peerStaticPublic)

    private var current: TrafficSession? = null
    private var previous: TrafficSession? = null
    private var pendingInitiator: PendingInitiator? = null
    private var pendingResponder: PendingResponder? = null
    private var awaitingFinishAck: AwaitingFinishAck? = null
    private var cookie: ByteArray? = null
    private var lastSentAt: Long = 0
    private var lastRxAt: Long = 0

    @Synchronized
    fun hasSession(now: Long = System.currentTimeMillis()): Boolean {
        prune(now)
        return current != null
    }

    @Synchronized
    fun currentSessionId(): Long = current?.id ?: 0L

    @Synchronized
    fun needsInitiatorHandshake(now: Long): Boolean {
        prune(now)
        expireUnresponsiveSession(now)
        if (current != null || pendingResponder != null || awaitingFinishAck != null) return false
        val pending = pendingInitiator ?: return true
        return now - pending.createdAt >= HANDSHAKE_RETRY_MS
    }

    @Synchronized
    fun createHandshakeInit(now: Long): ByteArray {
        val sessionId = TaltunCrypto.generateSessionId()
        val ephemeral = TaltunCrypto.generateKeyPair()
        val authTag = TaltunCrypto.handshakeInitAuthTag(
            staticShared,
            sessionId,
            localVip,
            peerVip,
            localStaticPublic,
            peerStaticPublic,
            ephemeral.publicKey,
        )
        val packet = TaltunProtocol.encodeHandshake(
            TaltunProtocol.MSG_HANDSHAKE_INIT,
            localVip,
            sessionId,
            localStaticPublic,
            ephemeral.publicKey,
            authTag,
            cookie,
        )
        pendingInitiator = PendingInitiator(sessionId, ephemeral, packet, now)
        lastSentAt = now
        return packet
    }

    @Synchronized
    fun setCookie(value: ByteArray) {
        if (value.size == TaltunProtocol.COOKIE_SIZE) cookie = value.copyOf()
    }

    @Synchronized
    fun handleHandshakeInit(handshake: TaltunProtocol.Handshake, now: Long): ByteArray? {
        if (handshake.type != TaltunProtocol.MSG_HANDSHAKE_INIT || !isExpectedPeer(handshake)) return null
        prune(now)
        if (sessionIdInUse(handshake.sessionId)) return null

        val ownPending = pendingInitiator
        if (current == null && ownPending != null) {
            if (Integer.compareUnsigned(localVip, peerVip) < 0) return null
            pendingInitiator = null
        }

        val existing = pendingResponder
        if (existing != null && existing.sessionId == handshake.sessionId &&
            existing.initiatorEphemeral.contentEquals(handshake.ephemeralPublic)
        ) {
            lastSentAt = now
            return existing.responsePacket.copyOf()
        }

        val valid = TaltunCrypto.constantTimeEquals(
            TaltunCrypto.handshakeInitAuthTag(
                staticShared,
                handshake.sessionId,
                peerVip,
                localVip,
                peerStaticPublic,
                localStaticPublic,
                handshake.ephemeralPublic,
            ),
            handshake.authTag,
        )
        if (!valid) return null
        lastRxAt = now

        val responderEphemeral = TaltunCrypto.generateKeyPair()
        val ephemeralShared = runCatching {
            TaltunCrypto.sharedSecret(responderEphemeral.privateKey, handshake.ephemeralPublic)
        }.getOrNull() ?: return null

        val keys = TaltunCrypto.deriveSessionKeys(
            staticShared,
            ephemeralShared,
            handshake.sessionId,
            peerVip,
            localVip,
            peerStaticPublic,
            localStaticPublic,
            handshake.ephemeralPublic,
            responderEphemeral.publicKey,
        )
        val responseTag = TaltunCrypto.handshakeResponseAuthTag(
            staticShared,
            handshake.sessionId,
            peerVip,
            localVip,
            peerStaticPublic,
            localStaticPublic,
            handshake.ephemeralPublic,
            responderEphemeral.publicKey,
        )
        val response = TaltunProtocol.encodeHandshake(
            TaltunProtocol.MSG_HANDSHAKE_RESP,
            localVip,
            handshake.sessionId,
            localStaticPublic,
            responderEphemeral.publicKey,
            responseTag,
        )
        pendingResponder = PendingResponder(
            handshake.sessionId,
            handshake.ephemeralPublic.copyOf(),
            responderEphemeral,
            keys,
            response,
        )
        lastSentAt = now
        return response
    }

    @Synchronized
    fun handleHandshakeResponse(handshake: TaltunProtocol.Handshake, now: Long): ByteArray? {
        if (handshake.type != TaltunProtocol.MSG_HANDSHAKE_RESP || !isExpectedPeer(handshake)) return null
        val pending = pendingInitiator ?: return null
        if (pending.sessionId != handshake.sessionId) return null

        val expectedTag = TaltunCrypto.handshakeResponseAuthTag(
            staticShared,
            handshake.sessionId,
            localVip,
            peerVip,
            localStaticPublic,
            peerStaticPublic,
            pending.ephemeral.publicKey,
            handshake.ephemeralPublic,
        )
        if (!TaltunCrypto.constantTimeEquals(expectedTag, handshake.authTag)) return null
        lastRxAt = now

        val ephemeralShared = runCatching {
            TaltunCrypto.sharedSecret(pending.ephemeral.privateKey, handshake.ephemeralPublic)
        }.getOrNull() ?: return null
        val keys = TaltunCrypto.deriveSessionKeys(
            staticShared,
            ephemeralShared,
            handshake.sessionId,
            localVip,
            peerVip,
            localStaticPublic,
            peerStaticPublic,
            pending.ephemeral.publicKey,
            handshake.ephemeralPublic,
        )
        val finishTag = TaltunCrypto.finishAuthTag(
            keys.finish,
            handshake.sessionId,
            localVip,
            peerVip,
            localStaticPublic,
            peerStaticPublic,
            pending.ephemeral.publicKey,
            handshake.ephemeralPublic,
        )
        installSession(
            handshake.sessionId,
            keys.initiatorToResponder,
            keys.responderToInitiator,
            now,
        )
        pendingInitiator = null
        pendingResponder = null
        val finish = TaltunProtocol.encodeHandshakeFinish(localVip, handshake.sessionId, finishTag)
        awaitingFinishAck = AwaitingFinishAck(handshake.sessionId, finish, 1, now)
        lastSentAt = now
        return finish
    }

    @Synchronized
    fun handleHandshakeFinish(finish: TaltunProtocol.HandshakeFinish, now: Long): Boolean {
        if (finish.senderVip != peerVip) return false
        val pending = pendingResponder ?: return false
        if (pending.sessionId != finish.sessionId) return false

        val expected = TaltunCrypto.finishAuthTag(
            pending.keys.finish,
            finish.sessionId,
            peerVip,
            localVip,
            peerStaticPublic,
            localStaticPublic,
            pending.initiatorEphemeral,
            pending.responderEphemeral.publicKey,
        )
        if (!TaltunCrypto.constantTimeEquals(expected, finish.authTag)) return false

        installSession(
            finish.sessionId,
            pending.keys.responderToInitiator,
            pending.keys.initiatorToResponder,
            now,
        )
        pendingResponder = null
        pendingInitiator = null
        awaitingFinishAck = null
        lastRxAt = now
        return true
    }

    @Synchronized
    fun finishRetransmission(now: Long): ByteArray? {
        val waiting = awaitingFinishAck ?: return null
        if (now - waiting.lastSentAt < HANDSHAKE_RETRY_MS) return null
        if (waiting.attempts >= FINISH_MAX_RETRIES) {
            if (current?.id == waiting.sessionId) {
                current = previous?.takeIf { now < it.expiresAt }
                previous = null
            }
            awaitingFinishAck = null
            return null
        }
        waiting.attempts++
        waiting.lastSentAt = now
        lastSentAt = now
        return waiting.packet.copyOf()
    }

    @Synchronized
    fun needsKeepalive(now: Long): Boolean = current != null && now - lastSentAt >= KEEPALIVE_MS

    @Synchronized
    fun seal(plaintext: ByteArray, now: Long): ByteArray? {
        prune(now)
        val session = current ?: return null
        val counter = session.txCounter.incrementAndGet()
        if (counter <= 0) return null
        val nonce = TaltunProtocol.nonce(counter)
        val header = TaltunProtocol.encodeDataHeader(localVip, session.id, nonce)
        val ciphertext = TaltunCrypto.seal(session.txKey, nonce, plaintext, header)
        lastSentAt = now
        return header + ciphertext
    }

    @Synchronized
    fun open(data: TaltunProtocol.DataHeader, now: Long): ByteArray? {
        if (data.senderVip != peerVip) return null
        prune(now)
        val session = when (data.sessionId) {
            current?.id -> current
            previous?.id -> previous
            else -> null
        } ?: return null
        val counter = TaltunProtocol.nonceCounter(data.nonce)
        if (counter <= 0) return null
        val plaintext = runCatching {
            TaltunCrypto.open(session.rxKey, data.nonce, data.ciphertext, data.aad)
        }.getOrNull() ?: return null
        if (!session.replay.validateAndUpdate(counter)) return null
        lastRxAt = now
        if (awaitingFinishAck?.sessionId == data.sessionId) awaitingFinishAck = null
        return plaintext
    }

    @Synchronized
    fun lastReceiveTime(): Long = lastRxAt

    private fun installSession(sessionId: Long, txKey: ByteArray, rxKey: ByteArray, now: Long) {
        current?.let {
            it.expiresAt = now + PREVIOUS_GRACE_MS
            previous = it
        }
        current = TrafficSession(sessionId, txKey.copyOf(), rxKey.copyOf(), now)
        prune(now)
    }

    private fun sessionIdInUse(sessionId: Long): Boolean =
        sessionId == 0L || current?.id == sessionId || previous?.id == sessionId || pendingResponder?.sessionId == sessionId

    private fun isExpectedPeer(handshake: TaltunProtocol.Handshake): Boolean =
        handshake.senderVip == peerVip && handshake.staticPublic.contentEquals(peerStaticPublic)

    private fun expireUnresponsiveSession(now: Long) {
        val active = current ?: return
        if (lastRxAt <= 0L || now - lastRxAt < SESSION_STALE_MS) return

        // Preserve the stale generation briefly so delayed packets can still
        // be authenticated while a fresh handshake is negotiated.
        active.expiresAt = now + PREVIOUS_GRACE_MS
        previous = active
        current = null
        pendingInitiator = null
        pendingResponder = null
        awaitingFinishAck = null
        lastRxAt = 0L
    }

    private fun prune(now: Long) {
        if (previous != null && now >= previous!!.expiresAt) previous = null
    }
}
