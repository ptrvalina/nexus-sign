package com.nexis.nexussign

import android.content.Context
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * The 12-word recovery phrase: BIP-39 encoding (English word list, 128 bits
 * of entropy plus a 4-bit checksum) used as a high-entropy recovery secret,
 * not as a BIP-39 seed. It is unrelated to the Keystore signing key and never
 * leaves the device; recovery protocol 2 derives from it only the key that
 * wraps the recovery key (see [RecoveryProtocol]).
 */
internal object RecoveryPhrase {

    private const val WORDLIST_ASSET = "bip39_english.txt"
    private const val WORD_COUNT = 12

    @Volatile private var cachedWordlist: List<String>? = null

    /** A fresh phrase from 128 bits of [SecureRandom] entropy. */
    fun generate(context: Context): List<String> {
        val entropy = ByteArray(16)
        SecureRandom().nextBytes(entropy)
        return wordsFromEntropy(wordlist(context), entropy)
    }

    /**
     * Splits pasted or typed input into lower-case words, so "Abandon  ABOUT"
     * and a phrase pasted into a single field are accepted. Must match
     * `RecoveryPhrase.normalized` on iOS and the shared recovery vectors
     * (`auth-core/test-vectors/recovery-v2.json`).
     */
    fun normalized(phrase: List<String>): List<String> =
        phrase.flatMap { it.split(WHITE_SPACE) }
            .filter { it.isNotEmpty() }
            .map { it.lowercase() }

    /** The Unicode White_Space characters, which Swift's `isWhitespace` splits
     * on. Java's `\s` is ASCII only: a phrase pasted with a no-break or
     * ideographic space was accepted on iOS and refused on Android (D-10). */
    private val WHITE_SPACE = Regex("[\\u0009-\\u000D\\u0020\\u0085\\u00A0\\u1680\\u2000-\\u200A\\u2028\\u2029\\u202F\\u205F\\u3000]+")

    /**
     * True if the phrase has 12 known words and a valid checksum. This is a
     * typo check before any network call, not a security boundary: whether
     * the phrase is the right one is decided by opening the wrapped recovery
     * key with it (the AES-GCM tag), and Auth Core accepts only a proof signed
     * with that recovery key.
     */
    fun isWellFormed(context: Context, phrase: List<String>): Boolean {
        val words = runCatching { wordlist(context) }.getOrNull() ?: return false
        return isWellFormed(words, phrase)
    }

    internal fun isWellFormed(wordlist: List<String>, phrase: List<String>): Boolean {
        val words = normalized(phrase)
        if (words.size != WORD_COUNT) return false
        val indices = words.map { wordlist.indexOf(it) }
        if (indices.any { it < 0 }) return false

        val bits = indices.joinToString("") { it.toString(2).padStart(11, '0') }
        val entropy = bytesFromBitString(bits.substring(0, 128))
        return bits.substring(128, 132) == checksumBits(entropy)
    }

    internal fun wordsFromEntropy(wordlist: List<String>, entropy: ByteArray): List<String> {
        require(entropy.size == 16) { "expected 128 bits of entropy" }
        val entropyBits = entropy.joinToString("") { (it.toInt() and 0xFF).toString(2).padStart(8, '0') }
        val allBits = entropyBits + checksumBits(entropy) // 132 bits = 12 groups of 11
        return (0 until WORD_COUNT).map { i -> wordlist[allBits.substring(i * 11, i * 11 + 11).toInt(2)] }
    }

    /** The top 4 bits of SHA-256(entropy), as BIP-39 specifies for 128-bit entropy. */
    private fun checksumBits(entropy: ByteArray): String {
        val firstByte = MessageDigest.getInstance("SHA-256").digest(entropy)[0].toInt() and 0xFF
        return firstByte.toString(2).padStart(8, '0').substring(0, 4)
    }

    private fun bytesFromBitString(bits: String): ByteArray =
        ByteArray(bits.length / 8) { i -> bits.substring(i * 8, i * 8 + 8).toInt(2).toByte() }

    private fun wordlist(context: Context): List<String> {
        cachedWordlist?.let { return it }
        synchronized(this) {
            cachedWordlist?.let { return it }
            val words = context.assets.open(WORDLIST_ASSET).bufferedReader(Charsets.UTF_8).use { reader ->
                reader.readLines().map { it.trim() }.filter { it.isNotEmpty() }
            }
            check(words.size == 2048) { "BIP-39 word list must contain 2048 words" }
            cachedWordlist = words
            return words
        }
    }
}
