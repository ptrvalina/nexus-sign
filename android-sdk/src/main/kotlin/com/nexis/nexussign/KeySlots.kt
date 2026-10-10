package com.nexis.nexussign

import android.content.Context

/** What Auth Core confirmed for a key set. Auth Core's offline key is used
 * once, to agree the offline key at enrolment, and not stored. */
internal data class Registration(
    val credentialId: String,
    val offlineServerPublicKeyPem: String?,
    /** Auth Core accepts device-signed requests for this credential. */
    val deviceSignatures: Boolean,
)

/** Persists which Keystore alias currently holds the registered credential. */
internal interface ActiveAliasStore {
    fun activeAlias(): String?
    /**
     * Switches to [alias] and records the [registration] that belongs to its
     * keys in the same durable write, so the device never holds new keys under
     * an old credential ID (or the reverse). Must be on disk when it returns:
     * the old keys are deleted right after.
     */
    fun setActiveAlias(alias: String, registration: Registration)
}

/** The credential ID Auth Core confirmed for this device, if any. */
internal interface CredentialStore {
    fun registeredCredentialId(): String?
    fun deviceSignatures(): Boolean
    fun clearRegistration()
}

/** Both stores, backed by one private SharedPreferences file per bank. */
internal class SharedPreferencesSdkState(context: Context, bankId: String) : ActiveAliasStore, CredentialStore {
    private val prefs = context.applicationContext.getSharedPreferences("com.nexis.nexussign.$bankId.keys", Context.MODE_PRIVATE)

    override fun activeAlias(): String? = prefs.getString(ACTIVE_ALIAS, null)

    override fun setActiveAlias(alias: String, registration: Registration) {
        // One commit(), not apply(): the previous keys are deleted immediately
        // after this returns, so pointer and registration must be on disk.
        val editor = prefs.edit()
            .putString(ACTIVE_ALIAS, alias)
            .putString(CREDENTIAL_ID, registration.credentialId)
            .putBoolean(DEVICE_SIGNATURES, registration.deviceSignatures)
        if (!editor.commit()) {
            throw NEXUSSignError.KeyOperationFailed(IllegalStateException("could not persist active key alias"))
        }
    }

    override fun registeredCredentialId(): String? = prefs.getString(CREDENTIAL_ID, null)

    override fun deviceSignatures(): Boolean = prefs.getBoolean(DEVICE_SIGNATURES, false)

    override fun clearRegistration() {
        prefs.edit().remove(CREDENTIAL_ID).commit()
    }

    private companion object {
        const val ACTIVE_ALIAS = "active_alias"
        const val CREDENTIAL_ID = "credential_id"
        const val DEVICE_SIGNATURES = "device_signatures"
    }
}

/**
 * Two Keystore slots for one bank's credential.
 *
 * Android Keystore entries cannot be renamed, so recovery generates the
 * replacement key in the spare slot and switches the active pointer only
 * once Auth Core has confirmed the recovery. Until then the existing key,
 * which may still be the valid registered credential, is untouched, and a
 * failed or interrupted recovery discards the spare slot.
 */
internal class KeySlots(private val primaryAlias: String, private val store: ActiveAliasStore) {
    private val secondaryAlias = "$primaryAlias.b"

    fun active(): String = store.activeAlias()?.takeIf { it == primaryAlias || it == secondaryAlias } ?: primaryAlias

    fun spare(): String = if (active() == primaryAlias) secondaryAlias else primaryAlias

    /** Switches to the spare slot with its registration; returns the retired alias. */
    fun promoteSpare(registration: Registration): String {
        val retired = active()
        store.setActiveAlias(spare(), registration)
        return retired
    }
}
