package com.soyunomas.taltun.android.core

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyFactory
import java.security.SecureRandom
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

object TaltunCrypto {
    const val KEY_SIZE = 32
    private val random = SecureRandom()

    // RFC 8410 DER prefixes for raw X25519 key material. Android's Conscrypt
    // accepts PKCS#8/X.509 EncodedKeySpec consistently across API 33+,
    // including releases where XECPrivateKeySpec/XECPublicKeySpec interop is provider-specific.
    private val x25519Pkcs8Prefix = byteArrayOf(
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
        0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
    )
    private val x25519X509Prefix = byteArrayOf(
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
        0x6e, 0x03, 0x21, 0x00,
    )

    data class RawKeyPair(val privateKey: ByteArray, val publicKey: ByteArray)
    data class SessionKeys(val initiatorToResponder: ByteArray, val responderToInitiator: ByteArray, val finish: ByteArray)

    fun generateKeyPair(): RawKeyPair {
        val privateKey = ByteArray(KEY_SIZE).also(random::nextBytes)
        return RawKeyPair(privateKey, publicFromPrivate(privateKey))
    }

    fun publicFromPrivate(privateKey: ByteArray): ByteArray {
        require(privateKey.size == KEY_SIZE)
        val basepoint = ByteArray(KEY_SIZE); basepoint[0] = 9
        return sharedSecret(privateKey, basepoint)
    }

    fun sharedSecret(privateKey: ByteArray, peerPublic: ByteArray): ByteArray {
        require(privateKey.size == KEY_SIZE && peerPublic.size == KEY_SIZE)
        val factory = x25519KeyFactory()
        val privateObject = factory.generatePrivate(
            PKCS8EncodedKeySpec(x25519Pkcs8Prefix + privateKey)
        )
        val publicObject = factory.generatePublic(
            X509EncodedKeySpec(x25519X509Prefix + peerPublic)
        )
        val agreement = x25519KeyAgreement()
        agreement.init(privateObject); agreement.doPhase(publicObject, true)
        val shared = agreement.generateSecret()
        if (shared.all { it == 0.toByte() }) throw IllegalArgumentException("invalid low-order X25519 public key")
        return shared
    }

    fun generateSessionId(): Long {
        while (true) {
            val value = ByteBuffer.wrap(ByteArray(8).also(random::nextBytes)).order(ByteOrder.BIG_ENDIAN).long
            if (value != 0L) return value
        }
    }

    fun handshakeInitAuthTag(staticShared: ByteArray, sessionId: Long, initiatorVip: Int, responderVip: Int, initiatorStatic: ByteArray, responderStatic: ByteArray, initiatorEphemeral: ByteArray): ByteArray =
        hmacSha256(staticShared, concat(ascii("taltun-handshake-init-v2"), sessionIdentity(sessionId, initiatorVip, responderVip), requireKey(initiatorStatic), requireKey(responderStatic), requireKey(initiatorEphemeral)))

    fun handshakeResponseAuthTag(staticShared: ByteArray, sessionId: Long, initiatorVip: Int, responderVip: Int, initiatorStatic: ByteArray, responderStatic: ByteArray, initiatorEphemeral: ByteArray, responderEphemeral: ByteArray): ByteArray =
        hmacSha256(staticShared, concat(ascii("taltun-handshake-response-v2"), sessionTranscriptHash(sessionId, initiatorVip, responderVip, initiatorStatic, responderStatic, initiatorEphemeral, responderEphemeral)))

    fun sessionTranscriptHash(sessionId: Long, initiatorVip: Int, responderVip: Int, initiatorStatic: ByteArray, responderStatic: ByteArray, initiatorEphemeral: ByteArray, responderEphemeral: ByteArray): ByteArray {
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        digest.update(ascii("taltun-session-transcript-v2"))
        digest.update(sessionIdentity(sessionId, initiatorVip, responderVip))
        digest.update(requireKey(initiatorStatic)); digest.update(requireKey(responderStatic)); digest.update(requireKey(initiatorEphemeral)); digest.update(requireKey(responderEphemeral))
        return digest.digest()
    }

    fun deriveSessionKeys(staticShared: ByteArray, ephemeralShared: ByteArray, sessionId: Long, initiatorVip: Int, responderVip: Int, initiatorStatic: ByteArray, responderStatic: ByteArray, initiatorEphemeral: ByteArray, responderEphemeral: ByteArray): SessionKeys {
        val transcript = sessionTranscriptHash(sessionId, initiatorVip, responderVip, initiatorStatic, responderStatic, initiatorEphemeral, responderEphemeral)
        val material = hkdfSha256(ephemeralShared, staticShared, concat(ascii("taltun-session-keys-v2"), transcript), KEY_SIZE * 3)
        return SessionKeys(material.copyOfRange(0, KEY_SIZE), material.copyOfRange(KEY_SIZE, KEY_SIZE * 2), material.copyOfRange(KEY_SIZE * 2, KEY_SIZE * 3))
    }

    fun finishAuthTag(finishKey: ByteArray, sessionId: Long, initiatorVip: Int, responderVip: Int, initiatorStatic: ByteArray, responderStatic: ByteArray, initiatorEphemeral: ByteArray, responderEphemeral: ByteArray): ByteArray =
        hmacSha256(requireKey(finishKey), concat(ascii("taltun-handshake-finish-v2"), sessionTranscriptHash(sessionId, initiatorVip, responderVip, initiatorStatic, responderStatic, initiatorEphemeral, responderEphemeral)))

    fun seal(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, aad: ByteArray): ByteArray {
        val cipher = chachaCipher()
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce)); cipher.updateAAD(aad)
        return cipher.doFinal(plaintext)
    }

    fun open(key: ByteArray, nonce: ByteArray, ciphertext: ByteArray, aad: ByteArray): ByteArray {
        val cipher = chachaCipher()
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce)); cipher.updateAAD(aad)
        return cipher.doFinal(ciphertext)
    }

    fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var diff = 0
        for (i in a.indices) diff = diff or (a[i].toInt() xor b[i].toInt())
        return diff == 0
    }

    private fun chachaCipher(): Cipher = try { Cipher.getInstance("ChaCha20-Poly1305") } catch (_: java.security.GeneralSecurityException) { Cipher.getInstance("ChaCha20/Poly1305/NoPadding") }

    private fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        val prk = hmacSha256(salt, ikm); val result = ByteArray(length); var previous = ByteArray(0); var written = 0; var counter = 1
        while (written < length) {
            previous = hmacSha256(prk, concat(previous, info, byteArrayOf(counter.toByte())))
            val copyLength = minOf(previous.size, length - written); previous.copyInto(result, written, 0, copyLength); written += copyLength; counter++
        }
        return result
    }

    private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray { val mac = Mac.getInstance("HmacSHA256"); mac.init(SecretKeySpec(key, "HmacSHA256")); return mac.doFinal(data) }
    private fun sessionIdentity(sessionId: Long, initiatorVip: Int, responderVip: Int): ByteArray = ByteBuffer.allocate(16).order(ByteOrder.BIG_ENDIAN).putLong(sessionId).putInt(initiatorVip).putInt(responderVip).array()
    private fun x25519KeyFactory(): KeyFactory =
        runCatching { KeyFactory.getInstance("XDH") }
            .getOrElse { KeyFactory.getInstance("X25519") }

    private fun x25519KeyAgreement(): KeyAgreement =
        runCatching { KeyAgreement.getInstance("XDH") }
            .getOrElse { KeyAgreement.getInstance("X25519") }

    private fun requireKey(value: ByteArray): ByteArray { require(value.size == KEY_SIZE); return value }
    private fun ascii(value: String) = value.toByteArray(Charsets.US_ASCII)
    private fun concat(vararg arrays: ByteArray): ByteArray { val out = ByteArray(arrays.sumOf { it.size }); var offset = 0; arrays.forEach { it.copyInto(out, offset); offset += it.size }; return out }
}
