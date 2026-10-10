package com.nexis.nexussign

import org.junit.Assert.assertThrows
import org.junit.Test

/** NXS-028: a release configuration cannot point the SDK at a cleartext server. */
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
}
