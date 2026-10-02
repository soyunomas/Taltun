package com.soyunomas.taltun.android.core

class ReplayWindow {
    companion object {
        const val WINDOW_SIZE = 2048
        private const val WORD_SIZE = 64
        private const val WORDS = WINDOW_SIZE / WORD_SIZE
    }

    private var lastSeq: Long = 0
    private val bitmap = LongArray(WORDS)

    @Synchronized
    fun validateAndUpdate(seq: Long): Boolean {
        if (seq <= 0L) return false
        if (seq > lastSeq) {
            val diff = seq - lastSeq
            if (diff >= WINDOW_SIZE) {
                bitmap.fill(0L)
                bitmap[0] = 1L
                lastSeq = seq
                return true
            }
            val shiftWords = (diff / WORD_SIZE).toInt()
            val shiftBits = (diff % WORD_SIZE).toInt()
            if (shiftWords > 0) {
                for (i in WORDS - 1 downTo shiftWords) bitmap[i] = bitmap[i - shiftWords]
                for (i in 0 until shiftWords) bitmap[i] = 0L
            }
            if (shiftBits > 0) {
                var carry = 0L
                for (i in 0 until WORDS) {
                    val newCarry = bitmap[i] ushr (WORD_SIZE - shiftBits)
                    bitmap[i] = (bitmap[i] shl shiftBits) or carry
                    carry = newCarry
                }
            }
            bitmap[0] = bitmap[0] or 1L
            lastSeq = seq
            return true
        }

        val diff = lastSeq - seq
        if (diff >= WINDOW_SIZE) return false
        val wordIndex = (diff / WORD_SIZE).toInt()
        val bitIndex = (diff % WORD_SIZE).toInt()
        val mask = 1L shl bitIndex
        if ((bitmap[wordIndex] and mask) != 0L) return false
        bitmap[wordIndex] = bitmap[wordIndex] or mask
        return true
    }
}
