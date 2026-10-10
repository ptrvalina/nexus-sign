package com.nexis.nexussign

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

/** Enrolment and recovery must never switch away from the registered keys
 * before Auth Core confirms, and must switch keys and registration together. */
class KeySlotsTest {

    private class MemoryStore(var value: String? = null) : ActiveAliasStore {
        var writes = 0
        var registration: Registration? = null
        override fun activeAlias(): String? = value
        override fun setActiveAlias(alias: String, registration: Registration) {
            value = alias
            this.registration = registration
            writes++
        }
    }

    private val confirmed = Registration("00000000-0000-4000-8000-000000000002", null, deviceSignatures = true)

    private val primary = "com.nexis.nexussign.bank.signingKey"

    @Test
    fun `fresh install uses the primary alias`() {
        val slots = KeySlots(primary, MemoryStore())
        assertEquals(primary, slots.active())
        assertNotEquals(slots.active(), slots.spare())
    }

    @Test
    fun `spare slot is used for recovery and active does not change until promotion`() {
        val store = MemoryStore()
        val slots = KeySlots(primary, store)
        val before = slots.active()
        val spare = slots.spare()
        assertEquals(before, slots.active())
        assertEquals(0, store.writes)

        val retired = slots.promoteSpare(confirmed)
        assertEquals(before, retired)
        assertEquals(spare, slots.active())
        assertEquals(1, store.writes)
        assertEquals("the registration is written with the pointer", confirmed, store.registration)
    }

    @Test
    fun `repeated recoveries alternate between the two slots`() {
        val slots = KeySlots(primary, MemoryStore())
        val seen = (1..4).map { slots.promoteSpare(confirmed); slots.active() }
        assertEquals(listOf("$primary.b", primary, "$primary.b", primary), seen)
    }

    @Test
    fun `an unknown stored alias falls back to the primary slot`() {
        val slots = KeySlots(primary, MemoryStore("some.other.alias"))
        assertEquals(primary, slots.active())
    }
}
