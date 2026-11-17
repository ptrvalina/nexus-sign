package com.nexis.nexussign

import org.junit.Assert.assertThrows
import org.junit.Test

/** A release configuration cannot point the SDK at a cleartext server. */
class NEXUSSignConfigTest {
    private fun config(baseUrl: String, allowEmulatorHostHttp: Boolean = false) =
        NEXUSSignConfig(bankId = "bank", baseUrl = baseUrl, sessionTokenProvider = { "token" }, allowEmulatorHostHttp = allowEmulatorHostHttp)

    @Test
    fun `https and on-device loopback are accepted`() {
        config("https://nexus.bank.example")
        config("http://127.0.0.1:8080")
        config("http://localhost:8080/")
    }

    @Test
    fun `the emulator host needs the explicit development flag`() {
        assertThrows(IllegalArgumentException::class.java) { config("http://10.0.2.2:8080") }
        config("http://10.0.2.2:8080", allowEmulatorHostHttp = true)
    }

    @Test
    fun `other cleartext hosts are refused even with the flag`() {
        for (url in listOf("http://nexus.bank.example", "http://10.0.2.20:8080", "http://127.0.0.1.evil.example", "http://10.0.2.2.evil.example")) {
            assertThrows(url, IllegalArgumentException::class.java) { config(url, allowEmulatorHostHttp = true) }
        }
    }

    private val pinA = "sha256/" + "A".repeat(43) + "="
    private val pinB = "sha256/" + "B".repeat(43) + "="
    private fun pinned(pins: List<String>, baseUrl: String = "https://nexus.bank.example") =
        NEXUSSignConfig(bankId = "bank", baseUrl = baseUrl, sessionTokenProvider = { "token" }, certificatePins = pins)

    @Test
    fun `pins need a backup pin, the sha256 form and https`() {
        pinned(emptyList())
        pinned(listOf(pinA, pinB))
        assertThrows(IllegalArgumentException::class.java) { pinned(listOf(pinA)) }
        assertThrows(IllegalArgumentException::class.java) { pinned(listOf(pinA, pinA)) }
        assertThrows(IllegalArgumentException::class.java) { pinned(listOf(pinA, "sha1/" + "B".repeat(27) + "=")) }
        assertThrows(IllegalArgumentException::class.java) { pinned(listOf(pinA, pinB), baseUrl = "http://127.0.0.1:8080") }
    }
}
