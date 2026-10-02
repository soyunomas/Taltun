package com.soyunomas.taltun.android.core

object Hex {
    private val digits = "0123456789abcdef".toCharArray()

    fun encode(bytes: ByteArray): String {
        val out = CharArray(bytes.size * 2)
        for (i in bytes.indices) {
            val value = bytes[i].toInt() and 0xff
            out[i * 2] = digits[value ushr 4]
            out[i * 2 + 1] = digits[value and 0x0f]
        }
        return String(out)
    }

    fun decode(value: String): ByteArray {
        val clean = value.trim()
        require(clean.length % 2 == 0) { "hex length must be even" }
        val out = ByteArray(clean.length / 2)
        for (i in out.indices) {
            val hi = Character.digit(clean[i * 2], 16)
            val lo = Character.digit(clean[i * 2 + 1], 16)
            require(hi >= 0 && lo >= 0) { "invalid hexadecimal value" }
            out[i] = ((hi shl 4) or lo).toByte()
        }
        return out
    }
}
