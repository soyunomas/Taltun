package com.soyunomas.taltun.android.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class TaltunProtocolTest {
    @Test
    fun dataHeaderRoundTrip() {
        val nonce = TaltunProtocol.nonce(0x0102030405060708L)
        val header = TaltunProtocol.encodeDataHeader(0x0a000002, 77, nonce)
        val parsed = TaltunProtocol.parseData(header + byteArrayOf(1, 2, 3))
        assertNotNull(parsed)
        assertEquals(0x0a000002, parsed!!.senderVip)
        assertEquals(77, parsed.sessionId)
        assertArrayEquals(nonce, parsed.nonce)
        assertArrayEquals(byteArrayOf(1, 2, 3), parsed.ciphertext)
    }

    @Test
    fun handshakeRoundTripWithCookie() {
        val packet = TaltunProtocol.encodeHandshake(
            TaltunProtocol.MSG_HANDSHAKE_INIT,
            1,
            55,
            ByteArray(32) { 1 },
            ByteArray(32) { 2 },
            ByteArray(32) { 3 },
            ByteArray(16) { 4 },
        )
        val parsed = TaltunProtocol.parseHandshake(packet)
        assertNotNull(parsed)
        assertEquals(55, parsed!!.sessionId)
        assertArrayEquals(ByteArray(16) { 4 }, parsed.cookie)
        assertNull(TaltunProtocol.parseHandshake(packet + 0))
    }

    @Test
    fun replayWindowAllowsReorderingButRejectsDuplicates() {
        val replay = ReplayWindow()
        assertTrue(replay.validateAndUpdate(1))
        assertTrue(replay.validateAndUpdate(3))
        assertTrue(replay.validateAndUpdate(2))
        assertFalse(replay.validateAndUpdate(2))
        assertTrue(replay.validateAndUpdate(3000))
        assertFalse(replay.validateAndUpdate(1))
    }
}
