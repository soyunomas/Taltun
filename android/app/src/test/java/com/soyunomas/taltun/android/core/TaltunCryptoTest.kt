package com.soyunomas.taltun.android.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class TaltunCryptoTest {
    private fun seq(start: Int) = ByteArray(32) { (start + it).toByte() }

    @Test
    fun matchesGoReferenceVectors() {
        val a = seq(0)
        val b = seq(32)
        val ae = seq(64)
        val be = seq(96)
        val aPub = TaltunCrypto.publicFromPrivate(a)
        val bPub = TaltunCrypto.publicFromPrivate(b)
        val aePub = TaltunCrypto.publicFromPrivate(ae)
        val bePub = TaltunCrypto.publicFromPrivate(be)

        assertEquals("8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f", Hex.encode(aPub))
        assertEquals("358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254", Hex.encode(bPub))

        val staticShared = TaltunCrypto.sharedSecret(a, bPub)
        val ephemeralShared = TaltunCrypto.sharedSecret(ae, bePub)
        assertEquals("9663aa1da97e848a914a436d04163dfbb89178f107f1b5b77ed3854203382854", Hex.encode(staticShared))
        assertEquals("d6fb939511b2381bc8599b4b8edc5968829450dfd7a87aebe78a703cd04cd54e", Hex.encode(ephemeralShared))

        val sid = 0x0102030405060708L
        val initiatorVip = Ipv4.parse("10.0.0.2")
        val responderVip = Ipv4.parse("10.0.0.1")
        assertEquals(
            "be4b28e26b514d25cc73999dafa06f7b95fe63f895f20634d110a89ff808c25a",
            Hex.encode(TaltunCrypto.handshakeInitAuthTag(staticShared, sid, initiatorVip, responderVip, aPub, bPub, aePub)),
        )
        assertEquals(
            "f6e6eaa1776f23f888553100a1726f8f98277713f0eeb84be7fbcc42db91df8a",
            Hex.encode(TaltunCrypto.handshakeResponseAuthTag(staticShared, sid, initiatorVip, responderVip, aPub, bPub, aePub, bePub)),
        )

        val keys = TaltunCrypto.deriveSessionKeys(
            staticShared, ephemeralShared, sid, initiatorVip, responderVip, aPub, bPub, aePub, bePub,
        )
        assertEquals("740ab1a6de5f2b3ad46296cc2bc562ebe4f3e84e8952c585260934b85dd8600f", Hex.encode(keys.initiatorToResponder))
        assertEquals("7566f3611b04730b1bddf18f029d00b420699aaafb16c341be61057ea640f748", Hex.encode(keys.responderToInitiator))
        assertEquals("9dc5dbb3a1f98d945dc8a4003b6e1529bc54edfaa89ca934b84c9770899dfc28", Hex.encode(keys.finish))
        assertEquals(
            "f6bb0ddae493c8d249fed2bca9d120862631623bfb44bfc2d7f0bc89adcb2d5f",
            Hex.encode(TaltunCrypto.finishAuthTag(keys.finish, sid, initiatorVip, responderVip, aPub, bPub, aePub, bePub)),
        )
    }

    @Test
    fun chachaHeaderIsAuthenticated() {
        val key = ByteArray(32) { it.toByte() }
        val nonce = TaltunProtocol.nonce(7)
        val header = TaltunProtocol.encodeDataHeader(Ipv4.parse("10.0.0.2"), 99, nonce)
        val plaintext = "hello".toByteArray()
        val ciphertext = TaltunCrypto.seal(key, nonce, plaintext, header)
        assertArrayEquals(plaintext, TaltunCrypto.open(key, nonce, ciphertext, header))

        val tampered = header.copyOf().also { it[4] = (it[4].toInt() xor 1).toByte() }
        assertThrows(Exception::class.java) { TaltunCrypto.open(key, nonce, ciphertext, tampered) }
    }

    @Test
    fun rejectsLowOrderX25519Point() {
        assertThrows(Exception::class.java) { TaltunCrypto.sharedSecret(seq(0), ByteArray(32)) }
    }
}
