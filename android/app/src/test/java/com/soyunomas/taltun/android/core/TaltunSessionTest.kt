package com.soyunomas.taltun.android.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class TaltunSessionTest {
    private fun seq(start: Int) = ByteArray(32) { (start + it).toByte() }

    private fun pair(): Pair<TaltunSession, TaltunSession> {
        val clientPriv = seq(0)
        val serverPriv = seq(32)
        val client = TaltunSession(
            Ipv4.parse("10.0.0.2"), clientPriv,
            Ipv4.parse("10.0.0.1"), TaltunCrypto.publicFromPrivate(serverPriv),
        )
        val server = TaltunSession(
            Ipv4.parse("10.0.0.1"), serverPriv,
            Ipv4.parse("10.0.0.2"), TaltunCrypto.publicFromPrivate(clientPriv),
        )
        return client to server
    }

    @Test
    fun establishesSessionAndTransportsData() {
        val (client, server) = pair()
        var now = 1_000L
        val init = client.createHandshakeInit(now)
        val response = server.handleHandshakeInit(TaltunProtocol.parseHandshake(init)!!, now + 1)
        assertNotNull(response)
        val finish = client.handleHandshakeResponse(TaltunProtocol.parseHandshake(response!!)!!, now + 2)
        assertNotNull(finish)
        assertTrue(server.handleHandshakeFinish(TaltunProtocol.parseHandshakeFinish(finish!!)!!, now + 3))

        val confirmation = server.seal(ByteArray(0), now + 4)!!
        assertArrayEquals(ByteArray(0), client.open(TaltunProtocol.parseData(confirmation)!!, now + 4))
        assertTrue(client.hasSession(now + 4))
        assertTrue(server.hasSession(now + 4))

        val plaintext = byteArrayOf(0x45, 0, 0, 20) + ByteArray(16)
        val packet = client.seal(plaintext, now + 5)!!
        val parsed = TaltunProtocol.parseData(packet)!!
        assertArrayEquals(plaintext, server.open(parsed, now + 5))
        assertFalse(server.open(parsed, now + 6) != null)
    }

    @Test
    fun retransmitsLostFinishAndRecovers() {
        val (client, server) = pair()
        val now = 10_000L
        val init = client.createHandshakeInit(now)
        val response = server.handleHandshakeInit(TaltunProtocol.parseHandshake(init)!!, now + 1)!!
        val firstFinish = client.handleHandshakeResponse(TaltunProtocol.parseHandshake(response)!!, now + 2)!!

        // Drop the first Finish. The client must resend the exact authenticated finish.
        val retry = client.finishRetransmission(now + 2 + TaltunSession.HANDSHAKE_RETRY_MS + 1)
        assertNotNull(retry)
        assertArrayEquals(firstFinish, retry)
        assertTrue(server.handleHandshakeFinish(TaltunProtocol.parseHandshakeFinish(retry!!)!!, now + 3_000))
        val confirmation = server.seal(ByteArray(0), now + 3_001)!!
        assertNotNull(client.open(TaltunProtocol.parseData(confirmation)!!, now + 3_001))
        assertTrue(client.hasSession(now + 3_001))
    }

    @Test
    fun acceptsServerInitiatedRekey() {
        val (client, server) = pair()
        var now = 20_000L
        fun complete(initiator: TaltunSession, responder: TaltunSession) {
            val init = initiator.createHandshakeInit(now++)
            val response = responder.handleHandshakeInit(TaltunProtocol.parseHandshake(init)!!, now++)!!
            val finish = initiator.handleHandshakeResponse(TaltunProtocol.parseHandshake(response)!!, now++)!!
            assertTrue(responder.handleHandshakeFinish(TaltunProtocol.parseHandshakeFinish(finish)!!, now++))
            val ack = responder.seal(ByteArray(0), now++)!!
            assertNotNull(initiator.open(TaltunProtocol.parseData(ack)!!, now++))
        }
        complete(client, server)
        val firstClientSession = client.currentSessionId()
        complete(server, client)
        assertTrue(client.currentSessionId() != firstClientSession)
        assertTrue(server.currentSessionId() == client.currentSessionId())
    }
    @Test
    fun staleEstablishedSessionForcesFreshHandshake() {
        val (client, server) = pair()
        val start = 40_000L

        val init = client.createHandshakeInit(start)
        val response = server.handleHandshakeInit(TaltunProtocol.parseHandshake(init)!!, start + 1)!!
        val finish = client.handleHandshakeResponse(TaltunProtocol.parseHandshake(response)!!, start + 2)!!
        assertTrue(server.handleHandshakeFinish(TaltunProtocol.parseHandshakeFinish(finish)!!, start + 3))

        val confirmation = server.seal(ByteArray(0), start + 4)!!
        assertNotNull(client.open(TaltunProtocol.parseData(confirmation)!!, start + 4))
        val oldSession = client.currentSessionId()

        assertFalse(client.needsInitiatorHandshake(start + 4 + TaltunSession.SESSION_STALE_MS - 1))
        assertTrue(client.needsInitiatorHandshake(start + 4 + TaltunSession.SESSION_STALE_MS))
        assertFalse(client.hasSession(start + 4 + TaltunSession.SESSION_STALE_MS))

        val freshInit = client.createHandshakeInit(start + 4 + TaltunSession.SESSION_STALE_MS)
        val freshResponse = server.handleHandshakeInit(
            TaltunProtocol.parseHandshake(freshInit)!!,
            start + 5 + TaltunSession.SESSION_STALE_MS,
        )!!
        val freshFinish = client.handleHandshakeResponse(
            TaltunProtocol.parseHandshake(freshResponse)!!,
            start + 6 + TaltunSession.SESSION_STALE_MS,
        )!!
        assertTrue(
            server.handleHandshakeFinish(
                TaltunProtocol.parseHandshakeFinish(freshFinish)!!,
                start + 7 + TaltunSession.SESSION_STALE_MS,
            ),
        )
        val freshAck = server.seal(ByteArray(0), start + 8 + TaltunSession.SESSION_STALE_MS)!!
        assertNotNull(
            client.open(
                TaltunProtocol.parseData(freshAck)!!,
                start + 8 + TaltunSession.SESSION_STALE_MS,
            ),
        )
        assertTrue(client.currentSessionId() != oldSession)
        assertTrue(client.currentSessionId() == server.currentSessionId())
    }

    @Test
    fun authenticatedTrafficRefreshesStaleTimer() {
        val (client, server) = pair()
        val start = 80_000L

        val init = client.createHandshakeInit(start)
        val response = server.handleHandshakeInit(TaltunProtocol.parseHandshake(init)!!, start + 1)!!
        val finish = client.handleHandshakeResponse(TaltunProtocol.parseHandshake(response)!!, start + 2)!!
        assertTrue(server.handleHandshakeFinish(TaltunProtocol.parseHandshakeFinish(finish)!!, start + 3))

        val firstAckTime = start + 4
        val confirmation = server.seal(ByteArray(0), firstAckTime)!!
        assertNotNull(client.open(TaltunProtocol.parseData(confirmation)!!, firstAckTime))

        val refreshTime = firstAckTime + TaltunSession.SESSION_STALE_MS - 1
        val keepalive = server.seal(ByteArray(0), refreshTime)!!
        assertNotNull(client.open(TaltunProtocol.parseData(keepalive)!!, refreshTime))

        assertFalse(client.needsInitiatorHandshake(firstAckTime + TaltunSession.SESSION_STALE_MS))
        assertTrue(client.hasSession(firstAckTime + TaltunSession.SESSION_STALE_MS))
    }

}
