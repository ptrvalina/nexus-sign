package com.nexis.nexussign

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Plain JVM tests: the word list is read from the same asset file the SDK
 * ships, so no Android runtime is needed.
 */
class RecoveryPhraseTest {

    private val wordlist: List<String> by lazy {
        val candidates = listOf("src/main/assets/bip39_english.txt", "android-sdk/src/main/assets/bip39_english.txt")
        val file = candidates.map(::File).first { it.isFile }
        file.readLines().map { it.trim() }.filter { it.isNotEmpty() }
    }

    private val allZero = List(11) { "abandon" } + "about" // BIP-39 vector for 16 zero bytes

    @Test
    fun `word list is the full BIP-39 English list`() {
        assertEquals(2048, wordlist.size)
        assertEquals("abandon", wordlist.first())
        assertEquals("zoo", wordlist.last())
    }

    @Test
    fun `encodes the BIP-39 reference vector`() {
        assertEquals(allZero, RecoveryPhrase.wordsFromEntropy(wordlist, ByteArray(16)))
        val ones = ByteArray(16) { 0xFF.toByte() }
        assertEquals(List(11) { "zoo" } + "wrong", RecoveryPhrase.wordsFromEntropy(wordlist, ones))
    }

    @Test
    fun `random phrases round-trip through validation`() {
        val random = java.security.SecureRandom()
        repeat(200) {
            val entropy = ByteArray(16).also(random::nextBytes)
            assertTrue(RecoveryPhrase.isWellFormed(wordlist, RecoveryPhrase.wordsFromEntropy(wordlist, entropy)))
        }
    }

    @Test
    fun `checksum, word count and unknown words are rejected`() {
        assertTrue(RecoveryPhrase.isWellFormed(wordlist, allZero))
        assertFalse(RecoveryPhrase.isWellFormed(wordlist, List(12) { "abandon" }))
        assertFalse(RecoveryPhrase.isWellFormed(wordlist, allZero.dropLast(1)))
        assertFalse(RecoveryPhrase.isWellFormed(wordlist, allZero.dropLast(1) + "notaword"))
    }

    @Test
    fun `pasted and mixed-case input is normalized`() {
        val typed = listOf("  Abandon", "ABANDON\n", "abandon abandon") + List(5) { "abandon" } + listOf("abandon\tabandon", "About ")
        assertEquals(allZero, RecoveryPhrase.normalized(typed))
        assertTrue(RecoveryPhrase.isWellFormed(wordlist, typed))
        assertTrue(RecoveryPhrase.isWellFormed(wordlist, listOf(allZero.joinToString("  "))))
    }

    @Test
    fun `Unicode spaces separate words as on iOS (D-10)`() {
        for (space in listOf("\u00A0", "\u3000", "\u2009", "\u202F", "\u2028", "\u0085")) {
            assertEquals(space, allZero, RecoveryPhrase.normalized(listOf(allZero.joinToString(space))))
        }
        // Not White_Space: the zero-width space and the BOM stay inside a word.
        assertFalse(RecoveryPhrase.isWellFormed(wordlist, listOf(allZero.joinToString("\u200B"))))
    }

    @Test
    fun `the recovery seed ignores formatting differences`() {
        val salt = ByteArray(16) { it.toByte() }
        val expected = RecoveryProtocol.seed(allZero, salt, 1_000)
        assertArrayEquals(expected, RecoveryProtocol.seed(listOf(allZero.joinToString(" ").uppercase()), salt, 1_000))
    }
}
