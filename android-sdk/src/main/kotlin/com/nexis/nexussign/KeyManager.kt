package com.nexis.nexussign

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.KeyProtection
import android.security.keystore.UserNotAuthenticatedException
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

/**
 * Owns the device's keys, all held in the Android Keystore and never exported:
 *
 * | Key | Use | Unlock |
 * |---|---|---|
 * | signing (EC P-256) | signs the canonical authorization bytes | biometric, every use (CryptoObject) |
 * | authentication (EC P-256) | signs each request to Auth Core | none (device must be unlocked) |
 * | offline (HMAC-SHA256) | computes offline confirmation codes | biometric, every use (CryptoObject) |
 *
 * The offline key is agreed with Auth Core once, at enrolment: an ephemeral
 * EC key pair (in memory only) and Auth Core's key give the shared HMAC key,
 * which is imported into the Keystore and then exists nowhere else on the
 * device. Binding its use to a `CryptoObject(Mac)` means a code can only be
 * computed through the prompt that shows the transaction.
 *
 * The three keys form a set in one [KeySlots] slot. Enrolment and recovery
 * generate a new set in the spare slot and switch to it only after Auth Core
 * confirms, so a failed attempt never destroys a working credential.
 *
 * StrongBox is used when the device has it; otherwise the keys are TEE-backed.
 * The signing and authentication keys are generated with a Keystore
 * attestation challenge derived from the enrolment challenge; their
 * attestation chains go to Auth Core, which decides from them, against the
 * bank's policy, whether the keys are acceptable (TEE, StrongBox, or refused).
 * The device's own report of the level is informational only.
 */
internal class KeyManager(config: NEXUSSignConfig, aliasStore: ActiveAliasStore) {

    enum class SecurityLevel { STRONGBOX, TRUSTED_EXECUTION_ENVIRONMENT, SOFTWARE_FALLBACK }

    /** One prepared key set: public halves of the Keystore keys with their
     * attestation chains (base64 DER, leaf first), and the ephemeral pair
     * from which the offline key is agreed with Auth Core. */
    class DeviceKeySet(
        val signing: PublicKey,
        val authentication: PublicKey,
        internal val offlineAgreement: KeyPair,
        val signingAttestation: List<String>,
        val authenticationAttestation: List<String>,
    ) {
        val offline: PublicKey get() = offlineAgreement.public
    }

    private val keyStore: KeyStore = try {
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    } catch (e: Exception) {
        throw NEXUSSignError.KeystoreUnavailable(e)
    }
    private val slots = KeySlots(config.keyAlias, aliasStore)

    private fun authAlias(slot: String) = "$slot.auth"
    private fun offlineAlias(slot: String) = "$slot.offline"

    fun hasExistingKey(): Boolean = contains(slots.active())

    fun hasAuthenticationKey(): Boolean = contains(authAlias(slots.active()))

    fun hasOfflineKey(): Boolean = contains(offlineAlias(slots.active()))

    private fun contains(alias: String): Boolean =
        try {
            keyStore.containsAlias(alias)
        } catch (e: Exception) {
            throw NEXUSSignError.KeystoreUnavailable(e)
        }

    // --- Enrolment and recovery (two-phase) ---

    /**
     * Step 1: a fresh key set in the spare slot; the active set is untouched.
     * [attestationChallenge] is set on the signing and authentication keys
     * (see [DeviceProtocol.keyAttestationChallenge]).
     */
    fun prepareReplacementKeys(attestationChallenge: ByteArray): DeviceKeySet {
        val spare = slots.spare()
        deleteSet(spare) // left over from an earlier, interrupted attempt
        return try {
            val signing = generate { signingSpec(spare, it, attestationChallenge) }
            val authentication = generate { authenticationSpec(authAlias(spare), it, attestationChallenge) }
            DeviceKeySet(
                signing = signing,
                authentication = authentication,
                offlineAgreement = KeyPairGenerator.getInstance("EC").run {
                    initialize(ECGenParameterSpec("secp256r1"))
                    generateKeyPair()
                },
                signingAttestation = attestationChain(spare),
                authenticationAttestation = attestationChain(authAlias(spare)),
            )
        } catch (e: NEXUSSignError) {
            deleteSet(spare)
            throw e
        } catch (e: Exception) {
            deleteSet(spare)
            throw NEXUSSignError.KeyOperationFailed(e)
        }
    }

    /**
     * Step 1b (Auth Core returned its key): agree the offline key and import it
     * into the spare slot. The shared secret and derived key are wiped.
     */
    fun installOfflineKey(prepared: DeviceKeySet, serverPublicKeyPem: String, credentialId: String) {
        val alias = offlineAlias(slots.spare())
        try {
            val serverKey = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(pemToDer(serverPublicKeyPem)))
            val shared = KeyAgreement.getInstance("ECDH").run {
                init(prepared.offlineAgreement.private)
                doPhase(serverKey, true)
                generateSecret()
            }
            val derived = DeviceProtocol.deriveOfflineKey(shared, credentialId)
            shared.fill(0)
            val protection = KeyProtection.Builder(KeyProperties.PURPOSE_SIGN)
                .setUserAuthenticationRequired(true)
                .setInvalidatedByBiometricEnrollment(true)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                protection.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            }
            try {
                keyStore.setEntry(alias, KeyStore.SecretKeyEntry(SecretKeySpec(derived, "HmacSHA256")), protection.build())
            } finally {
                derived.fill(0)
            }
        } catch (e: Exception) {
            throw NEXUSSignError.KeyOperationFailed(e)
        }
    }

    /** Step 2a (Auth Core confirmed): switch to the new set together with its
     * registration, then delete the old set. */
    fun commitReplacementKeys(registration: Registration) {
        deleteSet(slots.promoteSpare(registration))
    }

    /** Step 2b (attempt failed): discard the new set. */
    fun discardReplacementKeys() {
        deleteSet(slots.spare())
    }

    /** Security level of the prepared signing key, reported to Auth Core. */
    fun replacementSecurityLevel(): SecurityLevel = securityLevel(slots.spare())

    /** Best effort: a leftover key in an inactive slot is never used, and a
     * cleanup failure must not mask the error that triggered the cleanup. */
    private fun deleteSet(slot: String) {
        for (alias in listOf(slot, authAlias(slot), offlineAlias(slot))) {
            runCatching { if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias) }
        }
    }

    // --- Use ---

    /**
     * A [Signature] initialized with the signing key but not yet authorized:
     * `BiometricPrompt` must unlock it through a `CryptoObject`.
     *
     * @throws NEXUSSignError.CredentialInvalidated if the platform has
     *   invalidated the key (biometric enrolment changed); the set is deleted.
     */
    fun signatureForAuthorization(): Signature {
        val slot = slots.active()
        return withKeyErrors(slot) {
            val privateKey = keyStore.getKey(slot, null) as? PrivateKey ?: throw NEXUSSignError.NotRegistered
            Signature.getInstance("SHA256withECDSA").apply { initSign(privateKey) }
        }
    }

    /** Signs a request with the authentication key (DER). No user prompt;
     * fails with [NEXUSSignError.DeviceLocked] while the device is locked. */
    fun signRequest(input: ByteArray): ByteArray {
        val slot = slots.active()
        return withKeyErrors(slot, whenNotAuthenticated = NEXUSSignError.DeviceLocked) {
            val privateKey = keyStore.getKey(authAlias(slot), null) as? PrivateKey ?: throw NEXUSSignError.NotRegistered
            Signature.getInstance("SHA256withECDSA").run {
                initSign(privateKey)
                update(input)
                sign()
            }
        }
    }

    /**
     * A [Mac] initialized with the offline key but not yet authorized:
     * `BiometricPrompt` must unlock it through a `CryptoObject`.
     */
    fun offlineMac(): Mac {
        val slot = slots.active()
        return withKeyErrors(slot) {
            val key = keyStore.getKey(offlineAlias(slot), null) as? SecretKey ?: throw NEXUSSignError.OfflineConfirmationUnavailable
            Mac.getInstance("HmacSHA256").apply { init(key) }
        }
    }

    private inline fun <T> withKeyErrors(
        slot: String,
        whenNotAuthenticated: NEXUSSignError = NEXUSSignError.AuthenticationDenied("biometric confirmation required"),
        block: () -> T,
    ): T =
        try {
            block()
        } catch (e: KeyPermanentlyInvalidatedException) {
            deleteSet(slot)
            throw NEXUSSignError.CredentialInvalidated
        } catch (e: UserNotAuthenticatedException) {
            throw whenNotAuthenticated
        } catch (e: NEXUSSignError) {
            throw e
        } catch (e: Exception) {
            throw NEXUSSignError.KeyOperationFailed(e)
        }

    // --- Generation ---

    /** Generates with StrongBox if possible, else in the TEE. StrongBox
     * implementations differ in what they support, so any StrongBox failure
     * falls back rather than only StrongBoxUnavailableException. */
    private fun generate(spec: (strongBox: Boolean) -> KeyGenParameterSpec): PublicKey =
        try {
            try {
                generatePair(spec(true))
            } catch (e: Exception) {
                generatePair(spec(false))
            }
        } catch (e: Exception) {
            throw NEXUSSignError.KeyOperationFailed(e)
        }

    private fun generatePair(spec: KeyGenParameterSpec): PublicKey =
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE).run {
            initialize(spec)
            generateKeyPair().public
        }

    private fun ecBuilder(alias: String, purposes: Int, strongBox: Boolean, attestationChallenge: ByteArray): KeyGenParameterSpec.Builder =
        KeyGenParameterSpec.Builder(alias, purposes)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setAttestationChallenge(attestationChallenge)
            .also { if (strongBox) it.setIsStrongBoxBacked(true) }

    /** The key's attestation certificate chain from the Keystore, leaf first. */
    private fun attestationChain(alias: String): List<String> =
        keyStore.getCertificateChain(alias)?.map { Base64.getEncoder().encodeToString(it.encoded) }
            ?: throw NEXUSSignError.KeyOperationFailed(IllegalStateException("the Keystore returned no attestation chain"))

    private fun signingSpec(alias: String, strongBox: Boolean, attestationChallenge: ByteArray): KeyGenParameterSpec {
        val builder = ecBuilder(alias, KeyProperties.PURPOSE_SIGN, strongBox, attestationChallenge)
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
        }
        // On API 28-29 leaving the validity duration unset keeps the default:
        // authentication is required for every use of the key.
        return builder.build()
    }

    private fun authenticationSpec(alias: String, strongBox: Boolean, attestationChallenge: ByteArray): KeyGenParameterSpec =
        ecBuilder(alias, KeyProperties.PURPOSE_SIGN, strongBox, attestationChallenge)
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUnlockedDeviceRequired(true)
            .build()

    // --- Reporting ---

    /** Where the active signing key lives. */
    fun securityLevel(): SecurityLevel = securityLevel(slots.active())

    private fun securityLevel(alias: String): SecurityLevel {
        val keyInfo = try {
            val privateKey = keyStore.getKey(alias, null) as? PrivateKey
                ?: return SecurityLevel.SOFTWARE_FALLBACK
            KeyFactory.getInstance(privateKey.algorithm, ANDROID_KEYSTORE).getKeySpec(privateKey, KeyInfo::class.java)
        } catch (e: Exception) {
            throw NEXUSSignError.KeyOperationFailed(e)
        }

        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            when (keyInfo.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> SecurityLevel.STRONGBOX
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> SecurityLevel.TRUSTED_EXECUTION_ENVIRONMENT
                else -> SecurityLevel.SOFTWARE_FALLBACK
            }
        } else {
            @Suppress("DEPRECATION")
            if (keyInfo.isInsideSecureHardware) SecurityLevel.TRUSTED_EXECUTION_ENVIRONMENT else SecurityLevel.SOFTWARE_FALLBACK
        }
    }

    /** SPKI PEM, as Auth Core expects. [PublicKey.getEncoded] on Android EC
     * keys already returns X.509 SubjectPublicKeyInfo DER. */
    fun publicKeyPem(publicKey: PublicKey): String {
        val base64 = Base64.getEncoder().encodeToString(publicKey.encoded)
        val wrapped = base64.chunked(64).joinToString("\n")
        return "-----BEGIN PUBLIC KEY-----\n$wrapped\n-----END PUBLIC KEY-----"
    }

    private fun pemToDer(pem: String): ByteArray =
        Base64.getDecoder().decode(pem.lineSequence().filterNot { it.startsWith("-----") }.joinToString("").trim())

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
    }
}
