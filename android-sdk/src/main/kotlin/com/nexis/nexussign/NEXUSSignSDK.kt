package com.nexis.nexussign

import android.content.Context
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.time.Instant
import java.util.Base64
import javax.crypto.KeyAgreement
import javax.crypto.spec.SecretKeySpec
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * Native SDK embedded in the bank's existing Android application.
 *
 * The host application owns customer login, token issuance and all bank UI.
 * This SDK owns the device credential, transaction signing and the protocol
 * boundary with NEXUS-SIGN Auth Core.
 */
class NEXUSSignSDK(context: Context, private val config: NEXUSSignConfig) {
    private val appContext = context.applicationContext
    private val state = SharedPreferencesSdkState(appContext, config.bankId)
    private val keyManager = KeyManager(config, state)
    private val attestationProvider = AttestationProvider(appContext, config.playIntegrityCloudProjectNumber)
    private val networkClient = NetworkClient(config)
    private val pushKeys by lazy { PushKeyStore(appContext, config.bankId) }
    private val offlineSignatures by lazy { OfflineSignatureQueue(SharedPreferencesSignatureStorage(appContext, config.bankId)) }

    init {
        useDeviceAuthentication(state.registeredCredentialId())
    }

    /**
     * True once Auth Core has confirmed this device's credential (after
     * [bootstrap] or [recoverIdentity]) and the key is still present.
     */
    fun isRegistered(): Boolean = state.registeredCredentialId() != null && keyManager.hasExistingKey()

    /** True when this device can confirm transactions from a QR code without network. */
    /**
     * Fingerprint of this device's signing key: hex SHA-256 of its DER
     * SubjectPublicKeyInfo, computed here from the key in the Keystore, not
     * taken from any Auth Core response. After enrolment, replacement or
     * recovery the app sends it with the credential ID to the bank's own
     * backend, which approves exactly this key for the customer
     * (docs/protocol/bank-credential-trust-v1.md). Null when not registered.
     */
    fun signingKeyFingerprint(): String? =
        if (!isRegistered()) null else keyManager.activeSigningPublicKeyInfo()?.let(DeviceProtocol::signingKeyFingerprint)

    fun isOfflineConfirmationAvailable(): Boolean = isRegistered() && keyManager.hasOfflineKey()

    /** The credential ID confirmed by Auth Core, if the device is registered. */
    val credentialId: String? get() = state.registeredCredentialId()

    /**
     * Enrols this device with a BOOTSTRAP token from the host app: generates
     * the signing, authentication and offline keys, and registers
     * them with one Play Integrity attestation covering all three and a
     * Keystore attestation of each hardware key. Afterwards
     * the device signs its own requests and needs no further token. A
     * customer who already has an enrolled device can only be enrolled with
     * a replacement token the bank issues after re-identifying them (Auth Core
     * answers 409 otherwise); if enrolment fails, the previous keys stay in place.
     */
    suspend fun bootstrap(): NexusMobileRegistration {
        val bootstrapToken = config.sessionTokenProvider(NEXUSTokenPurpose.BOOTSTRAP)
        val challenge = MessageDigest.getInstance("SHA-256").digest(bootstrapToken.toByteArray(Charsets.UTF_8))
        val registration = withReplacementKeys(
            attestationChallenge = challenge,
            register = { keys, securityLevel -> networkClient.bootstrap(keys, securityLevel, attestationPayload(challenge, keys), bootstrapToken) },
            confirmed = { Registration(it.credentialId, it.offlineServerPublicKeyPem, it.requestAuthentication == "DEVICE_SIGNATURE") },
        )
        useDeviceAuthentication(registration.credentialId)
        return registration
    }

    /**
     * Fetches an authorization and verifies that its displayable fields match
     * the exact bytes the device would sign. Throws
     * [NEXUSSignError.AuthorizationPayloadInvalid] if they do not.
     *
     * Render the confirmation screen from [NexusAuthorization.signedTransaction],
     * which holds the values that will be signed.
     */
    suspend fun fetchAuthorization(authorizationId: String): NexusAuthorization {
        // The ID may come from a push or deep link: it must not steer the
        // signed request to another endpoint.
        if (!UUID_PATTERN.matches(authorizationId)) {
            throw NEXUSSignError.AuthorizationPayloadInvalid("invalid_id", "authorizationId")
        }
        val authorization = networkClient.fetchAuthorization(authorizationId)
        if (authorization.authorizationId != authorizationId) {
            throw NEXUSSignError.AuthorizationPayloadInvalid("response_mismatch", "authorizationId")
        }
        authorization.signedTransaction()
        return authorization
    }

    /** The transaction exactly as it will be signed; use this for display. */
    fun signedTransaction(authorization: NexusAuthorization): NexusSignedTransaction = authorization.signedTransaction()

    /**
     * Shows the biometric prompt with the signed transaction text, signs the
     * canonical bytes and submits the signature. Call from the main thread's
     * lifecycle scope of [activity].
     */
    /**
     * Opens an audio or video verification session for [authorization], when
     * the bank's verification plan asks for one (ADR 0017). The signed bytes
     * are verified first, so the terms shown during the call
     * ([NexusSignedTransaction.confirmationText]) are the ones the operator
     * sees and the device will sign. Auth Core binds the session to this
     * authorization and this device's credential. At most three sessions per
     * channel and authorization.
     *
     * Run the call with [callSignalling] and a media engine
     * (nexus-sign-android-calls). The call never confirms the payment: after
     * a VERIFIED decision, call [approve] as usual.
     */
    suspend fun openVerificationCall(authorization: NexusAuthorization, channel: VerificationChannel): VerificationSession {
        val signed = authorization.signedTransaction()
        requireNotExpired(signed)
        if (!isRegistered()) throw NEXUSSignError.NotRegistered
        if (signed.credentialId != state.registeredCredentialId()) {
            throw NEXUSSignError.AuthorizationPayloadInvalid("wrong_device", "the authorization is for another device")
        }
        return CallWire.decodeSession(networkClient.openVerificationSession(authorization.authorizationId, channel), authorization.authorizationId)
    }

    /** Device-signed signalling of one verification session. */
    fun callSignalling(session: VerificationSession): CallSignalling {
        if (!isRegistered()) throw NEXUSSignError.NotRegistered
        return DeviceCallSignalling(session.sessionId, networkClient)
    }

    suspend fun approve(authorization: NexusAuthorization, activity: FragmentActivity): NEXUSVerificationOutcome {
        // Expiry, prompt text and the signed bytes all come from the one
        // verified canonical payload, never from the JSON convenience fields.
        val signed = authorization.signedTransaction()
        val canonicalBytes = Base64.getDecoder().decode(authorization.canonicalPayloadBase64)
        requireNotExpired(signed)
        if (!isRegistered()) throw NEXUSSignError.NotRegistered
        if (signed.credentialId != state.registeredCredentialId()) {
            throw NEXUSSignError.AuthorizationPayloadInvalid("wrong_device", "the authorization is for another device")
        }
        requireBiometrics(activity)

        val signature = try {
            keyManager.signatureForAuthorization()
        } catch (e: NEXUSSignError.CredentialInvalidated) {
            forgetRegistration()
            throw e
        }
        val authorized = authenticate(activity, BiometricPrompt.CryptoObject(signature), signed.confirmationText())
            .cryptoObject?.signature ?: signature
        val signatureDer = try {
            authorized.update(canonicalBytes)
            authorized.sign()
        } catch (e: Exception) {
            throw NEXUSSignError.KeyOperationFailed(e)
        }

        val response = try {
            networkClient.signAuthorization(signed.authorizationId, signatureDer)
        } catch (e: NEXUSSignError.ServerError) {
            if (e.statusCode == 410) throw NEXUSSignError.AuthorizationExpired
            throw e
        }
        return NEXUSVerificationOutcome.entries.firstOrNull { it.name == response.status }
            ?: throw NEXUSSignError.ServerError(200, "Unexpected verification status")
    }

    /**
     * Generates a 12-word recovery phrase, registers a recovery key protected
     * by it with Auth Core (recovery protocol 2), and returns the words for
     * the customer to write down. The phrase never leaves the device. The
     * customer confirms with biometrics, because a new phrase replaces the
     * previous one.
     */
    suspend fun generateRecoveryPhrase(activity: FragmentActivity): List<String> {
        val credentialId = state.registeredCredentialId() ?: throw NEXUSSignError.NotRegistered
        val parameters = networkClient.recoveryParameters()
        val salt = validated(parameters)
        val nexusId = parameters.nexusId
        if (nexusId == null || parameters.credentialId != credentialId) {
            throw NEXUSSignError.ServerError(0, "Recovery parameters are for another device")
        }
        requireBiometrics(activity)
        val phrase = RecoveryPhrase.generate(appContext)

        val recoveryKey = RecoveryProtocol.newRecoveryKey()
        val recoverySpki = recoveryKey.public.encoded
        val seed = RecoveryProtocol.seed(phrase, salt, parameters.iterations)
        val wrapKey = RecoveryProtocol.wrapKey(seed, nexusId)
        val scalar = RecoveryProtocol.scalar(recoveryKey.private)
        val wrapped = try {
            RecoveryProtocol.wrap(scalar, wrapKey, RecoveryProtocol.associatedData(nexusId, recoverySpki))
        } finally {
            seed.fill(0)
            wrapKey.fill(0)
            scalar.fill(0)
        }

        val signature = try {
            keyManager.signatureForAuthorization()
        } catch (e: NEXUSSignError.CredentialInvalidated) {
            forgetRegistration()
            throw e
        }
        val authorized = authenticate(activity, BiometricPrompt.CryptoObject(signature), config.recoverySetupPromptText)
            .cryptoObject?.signature ?: signature
        val signatureDer = try {
            authorized.update(RecoveryProtocol.setupSigningInput(nexusId, credentialId, parameters.salt, recoverySpki, wrapped))
            authorized.sign()
        } catch (e: Exception) {
            throw NEXUSSignError.KeyOperationFailed(e)
        }
        networkClient.configureRecovery(parameters.salt, keyManager.publicKeyPem(recoveryKey.public), wrapped, signatureDer)
        return phrase
    }

    /**
     * Recovers the customer's identity on this device with the recovery
     * phrase. [session] is created by the bank backend after it has
     * re-identified the customer.
     */
    suspend fun recoverIdentity(session: NexusRecoverySession, recoveryPhrase: List<String>): NexusRecoveryResult {
        val words = RecoveryPhrase.normalized(recoveryPhrase)
        if (!RecoveryPhrase.isWellFormed(appContext, words)) throw NEXUSSignError.InvalidRecoveryPhrase
        // The session ID comes from the host app and becomes part of the path.
        if (!UUID_PATTERN.matches(session.sessionId)) throw NEXUSSignError.ServerError(0, "Invalid recovery session")
        val nonce = runCatching { Base64.getDecoder().decode(session.nonce) }.getOrElse {
            throw NEXUSSignError.ServerError(0, "Invalid recovery session")
        }
        val salt = validated(session.parameters)
        val recoveryPublicKeyPem = session.recoveryPublicKeyPem
        val wrapped = session.wrappedRecoveryKey?.let { runCatching { Base64.getDecoder().decode(it) }.getOrNull() }
        if (recoveryPublicKeyPem == null || wrapped == null) throw NEXUSSignError.ServerError(0, "Invalid recovery session")

        // A wrong phrase fails here, on the device, without using an attempt.
        val seed = RecoveryProtocol.seed(words, salt, session.parameters.iterations)
        val wrapKey = RecoveryProtocol.wrapKey(seed, session.nexusId)
        val scalar = try {
            RecoveryProtocol.unwrap(wrapped, wrapKey, RecoveryProtocol.associatedData(session.nexusId, RecoveryProtocol.spkiFromPem(recoveryPublicKeyPem)))
        } finally {
            seed.fill(0)
            wrapKey.fill(0)
        }
        val recoveryKey = try {
            RecoveryProtocol.privateKey(scalar)
        } finally {
            scalar.fill(0)
        }

        // The replacement keys live in the spare slot until Auth Core confirms
        // the recovery. A network failure or an interrupted call leaves the
        // current keys untouched.
        val result = try {
            withReplacementKeys(
                attestationChallenge = nonce,
                register = { keys, securityLevel ->
                    val proof = RecoveryProtocol.sign(recoveryKey,
                        RecoveryProtocol.proofSigningInput(session.sessionId, session.nonce, session.nexusId, RecoveryProtocol.spkiFromPem(keys.signing)))
                    networkClient.recover(session, proof, keys, securityLevel, attestationPayload(nonce, keys))
                },
                confirmed = { Registration(it.credentialId, it.offlineServerPublicKeyPem, it.requestAuthentication == "DEVICE_SIGNATURE") },
            )
        } catch (e: NEXUSSignError.ServerError) {
            // 401: Auth Core refused the proof (a wrong phrase normally fails
            // earlier, on the device); reported as a wrong phrase.
            throw if (e.statusCode == 401) NEXUSSignError.InvalidRecoveryPhrase else e
        }
        useDeviceAuthentication(result.credentialId)
        return result
    }

    /**
     * Reads an offline QR code shown by the bank (branch, ATM, web banking)
     * and verifies it exactly as [fetchAuthorization] verifies an online
     * authorization. No network is used. Render the confirmation screen from
     * [NexusOfflineChallenge.transaction].
     */
    fun readOfflineChallenge(qrPayload: String): NexusOfflineChallenge {
        val version = DeviceProtocol.qrPayloadVersion(qrPayload)
        val bytes = DeviceProtocol.qrPayloadBytes(qrPayload)
        val transaction = try {
            SignedPayload.parse(bytes)
        } catch (e: SignedPayload.Rejected) {
            throw NEXUSSignError.AuthorizationPayloadInvalid(e.reason, e.message ?: e.reason)
        }
        if (transaction.credentialId != state.registeredCredentialId()) {
            throw NEXUSSignError.AuthorizationPayloadInvalid("wrong_device", "the QR code is for another device")
        }
        requireNotExpired(transaction)
        return NexusOfflineChallenge(transaction, bytes, requiresDeviceSignature = version == 2)
    }

    /**
     * Asks for biometric confirmation showing the transaction and returns the
     * 8-digit code the customer types on the bank's screen. Works without
     * network. The code is valid only for this exact transaction.
     *
     * Offline confirmation v2 ([NexusOfflineChallenge.requiresDeviceSignature]):
     * first the signing key signs the transaction (its own prompt: Android
     * binds one key to one prompt) and the signature is stored; only then is
     * the code computed (second prompt). Auth Core confirms the payment when
     * the signature arrives: call [submitPendingOfflineSignatures] whenever
     * the app is online.
     */
    suspend fun confirmOffline(challenge: NexusOfflineChallenge, activity: FragmentActivity): String {
        if (state.registeredCredentialId() == null) throw NEXUSSignError.NotRegistered
        if (!keyManager.hasOfflineKey()) throw NEXUSSignError.OfflineConfirmationUnavailable
        requireNotExpired(challenge.transaction)
        requireBiometrics(activity)

        if (challenge.requiresDeviceSignature) {
            val authorizationId = challenge.transaction.authorizationId
            if (!UUID_PATTERN.matches(authorizationId)) throw NEXUSSignError.AuthorizationPayloadInvalid("invalid_qr", "authorization ID is not a UUID")
            val signature = try {
                keyManager.signatureForAuthorization()
            } catch (e: NEXUSSignError.CredentialInvalidated) {
                forgetRegistration()
                throw e
            }
            val authorized = authenticate(activity, BiometricPrompt.CryptoObject(signature), challenge.transaction.confirmationText())
                .cryptoObject?.signature ?: signature
            val signatureDer = try {
                authorized.update(challenge.canonicalPayload)
                authorized.sign()
            } catch (e: Exception) {
                throw NEXUSSignError.KeyOperationFailed(e)
            }
            // Stored before the code exists: no code without its signature.
            offlineSignatures.add(authorizationId, Base64.getEncoder().encodeToString(signatureDer))
        }

        val mac = try {
            keyManager.offlineMac()
        } catch (e: NEXUSSignError.CredentialInvalidated) {
            forgetRegistration()
            throw e
        }
        // The key can be used only through this prompt, which shows the transaction.
        val unlocked = authenticate(activity, BiometricPrompt.CryptoObject(mac), challenge.transaction.confirmationText())
            .cryptoObject?.mac ?: mac
        val tag = try {
            unlocked.doFinal(DeviceProtocol.offlineTagInput(challenge.canonicalPayload))
        } catch (e: Exception) {
            throw NEXUSSignError.KeyOperationFailed(e)
        }
        return DeviceProtocol.offlineCode(tag)
    }

    /**
     * Offline confirmation v2: uploads the signatures made by [confirmOffline]
     * that Auth Core does not have yet. Call it when the app starts and
     * whenever it regains a connection. Signatures Auth Core accepted, or can
     * never accept (the payment was finalized otherwise, or the signature is
     * not valid for it), are removed; the others are kept for the next call.
     */
    suspend fun submitPendingOfflineSignatures(): OfflineSignatureDelivery {
        if (state.registeredCredentialId() == null) return OfflineSignatureDelivery(0, 0, offlineSignatures.pending().size)
        return offlineSignatures.deliver { item ->
            if (!UUID_PATTERN.matches(item.authorizationId)) return@deliver UploadOutcome.Refused(0)
            try {
                UploadOutcome.ofStatus(networkClient.uploadDeferredSignature(item.authorizationId, item.signature))
            } catch (e: NEXUSSignError.ServerError) {
                UploadOutcome.ofStatus(e.statusCode)
            } catch (e: NEXUSSignError.NetworkUnavailable) {
                UploadOutcome.Retry
            }
        }
    }

    // --- Secure push (bank push mode NEXUS) ---

    /**
     * Registers this device for NEXUS-SIGN secure push with the FCM token from
     * the app's `FirebaseMessagingService.onNewToken`. Call it at every launch,
     * whenever the token changes, and after [bootstrap] or recovery: a new
     * credential agrees a new push key.
     */
    suspend fun registerPush(fcmToken: String): Unit = pushRegistrationLock.withLock {
        // One registration at a time: two concurrent agreements could leave
        // the device with a different key from Auth Core's.
        val credentialId = state.registeredCredentialId() ?: throw NEXUSSignError.NotRegistered
        val existing = pushKeys.keysFor(credentialId)
        if (existing != null) {
            try {
                networkClient.registerPush(fcmToken, devicePublicKeyPem = null, keyId = PushProtocol.keyId(existing.second))
                return@withLock
            } catch (e: NEXUSSignError.ServerError) {
                // 409: Auth Core holds another key (or none) for this device; agree a new one.
                if (e.statusCode != 409) throw e
            }
        }
        // An agreement whose answer is lost must not leave a stale key behind.
        pushKeys.delete()
        // Ephemeral key pair, in memory only; the agreed key is all that is kept.
        val ephemeral = KeyPairGenerator.getInstance("EC").run {
            initialize(ECGenParameterSpec("secp256r1"))
            generateKeyPair()
        }
        val response = networkClient.registerPush(fcmToken, keyManager.publicKeyPem(ephemeral.public), keyId = null)
        val serverPem = response.serverPublicKeyPem ?: throw NEXUSSignError.ServerError(200, "Auth Core returned no push key agreement")
        val shared = try {
            val serverKey = KeyFactory.getInstance("EC").generatePublic(
                X509EncodedKeySpec(Base64.getDecoder().decode(serverPem.lineSequence().filterNot { it.startsWith("-----") }.joinToString("").trim())),
            )
            KeyAgreement.getInstance("ECDH").run {
                init(ephemeral.private)
                doPhase(serverKey, true)
                generateSecret()
            }
        } catch (e: Exception) {
            throw NEXUSSignError.KeyOperationFailed(e)
        }
        val key = try {
            PushProtocol.derivePushKey(shared, credentialId)
        } finally {
            shared.fill(0)
        }
        if (PushProtocol.keyId(SecretKeySpec(key, "HmacSHA256")) != response.keyId) {
            key.fill(0)
            throw NEXUSSignError.ServerError(200, "Push key agreement did not match")
        }
        pushKeys.install(key, credentialId) // wipes `key`
    }

    /** Stops secure push to this device and deletes its push key. */
    suspend fun unregisterPush() {
        // The local push key goes even when Auth Core cannot be told (offline,
        // or a device that can no longer sign requests).
        try {
            networkClient.unregisterPush()
        } finally {
            pushKeys.delete()
        }
    }

    /**
     * Opens a message from `RemoteMessage.data` in the app's
     * `FirebaseMessagingService.onMessageReceived`; works while the phone is
     * locked. Returns `null` for messages that are not NEXUS-SIGN secure push.
     * Show the result as a notification, then call [confirmPushReceipt].
     */
    fun openPush(data: Map<String, String>): NexusPushMessage? {
        val envelope = PushMessages.envelopeOf(data) ?: return null
        return open(envelope)
    }

    /** Fetches and opens a message by ID, for when the app opens before the push arrives. */
    suspend fun fetchPushMessage(messageId: String): NexusPushMessage {
        if (!UUID_PATTERN.matches(messageId)) throw NEXUSSignError.PushMessageInvalid("malformed_envelope")
        val response = networkClient.fetchPushEnvelope(messageId)
        if (response.envelope.id != messageId || response.envelope.cid != state.registeredCredentialId()) {
            throw NEXUSSignError.PushMessageInvalid("malformed_envelope")
        }
        return open(response.envelope)
    }

    /**
     * Confirms to Auth Core that the message reached the customer; the bank
     * receives push.delivered. Authenticated by the push key, so it also works
     * while the phone is locked.
     */
    suspend fun confirmPushReceipt(message: NexusPushMessage) {
        val (_, macKey) = pushKeys.keysFor(message.credentialId) ?: throw NEXUSSignError.PushMessageInvalid("no_push_key")
        networkClient.sendPushReceipt(message.messageId, message.credentialId, PushProtocol.receipt(macKey, message.messageId, message.credentialId))
    }

    /**
     * The customer refuses the payment instead of confirming it. The bank
     * receives `authorization.declined` with the reason; the authorization can
     * no longer be confirmed.
     */
    suspend fun decline(authorization: NexusAuthorization, reason: NexusDeclineReason) {
        if (!UUID_PATTERN.matches(authorization.authorizationId)) throw NEXUSSignError.AuthorizationPayloadInvalid("invalid_id", "authorization ID is not a UUID")
        networkClient.declineAuthorization(authorization.authorizationId, reason)
    }

    /** Open device replacements the bank requested for this NEXUS ID; show them on this (enrolled) device. */
    suspend fun pendingDeviceReplacements(): List<NexusDeviceReplacement> = networkClient.deviceReplacements()

    /** The customer confirms the replacement: the new device can be enrolled now instead of after the hold. */
    suspend fun approveDeviceReplacement(replacementId: String): NexusDeviceReplacement =
        networkClient.decideDeviceReplacement(requireReplacementId(replacementId), approve = true)

    /** The customer refuses the replacement ("it wasn't me"); it can never be used. */
    suspend fun cancelDeviceReplacement(replacementId: String): NexusDeviceReplacement =
        networkClient.decideDeviceReplacement(requireReplacementId(replacementId), approve = false)

    private fun requireReplacementId(id: String): String {
        if (!UUID_PATTERN.matches(id)) throw NEXUSSignError.ServerError(400, "Malformed replacement ID")
        return id
    }

    private fun open(envelope: NexusPushEnvelope): NexusPushMessage {
        if (!PushMessages.isWellFormed(envelope)) throw NEXUSSignError.PushMessageInvalid("malformed_envelope")
        val (decryptKey, _) = pushKeys.keysFor(envelope.cid) ?: throw NEXUSSignError.PushMessageInvalid("no_push_key")
        return PushMessages.parse(envelope, PushProtocol.open(envelope, decryptKey))
    }

    /**
     * Runs one enrolment or recovery attempt with a fresh key set. The new
     * keys, including the offline key agreed with Auth Core's answer, replace
     * the old ones only if [register] succeeds, in one durable write together
     * with the [confirmed] registration; otherwise they are discarded.
     */
    private suspend fun <T> withReplacementKeys(
        attestationChallenge: ByteArray,
        register: suspend (NetworkClient.EnrolmentKeys, String) -> T,
        confirmed: (T) -> Registration,
    ): T = replacementLock.withLock {
        // Without a screen lock the authentication key would need no user at
        // all: enrolment requires a secure lock screen.
        val keyguard = appContext.getSystemService(Context.KEYGUARD_SERVICE) as android.app.KeyguardManager
        if (!keyguard.isDeviceSecure) throw NEXUSSignError.NoAuthenticationMethodEnrolled
        // One attempt at a time per process: two attempts would share the
        // spare key slot, and the second would overwrite the first's keys.
        val prepared = keyManager.prepareReplacementKeys(DeviceProtocol.keyAttestationChallenge(attestationChallenge))
        val result = try {
            val keys = NetworkClient.EnrolmentKeys(
                signing = keyManager.publicKeyPem(prepared.signing),
                authentication = keyManager.publicKeyPem(prepared.authentication),
                offline = keyManager.publicKeyPem(prepared.offline),
                signingAttestation = prepared.signingAttestation,
                authenticationAttestation = prepared.authenticationAttestation,
            )
            register(keys, keyManager.replacementSecurityLevel().name).also { response ->
                val registration = confirmed(response)
                registration.offlineServerPublicKeyPem?.let {
                    keyManager.installOfflineKey(prepared, it, registration.credentialId)
                }
            }
        } catch (e: Throwable) {
            keyManager.discardReplacementKeys()
            throw e
        }
        keyManager.commitReplacementKeys(confirmed(result))
        result
    }

    private fun useDeviceAuthentication(credentialId: String?) {
        networkClient.deviceIdentity = if (credentialId != null && keyManager.hasAuthenticationKey() && state.deviceSignatures()) {
            NetworkClient.DeviceIdentity(credentialId) { input -> keyManager.signRequest(input) }
        } else {
            null
        }
    }

    private fun forgetRegistration() {
        state.clearRegistration()
        networkClient.deviceIdentity = null
    }

    private fun requireNotExpired(transaction: NexusSignedTransaction) {
        val expiry = runCatching { Instant.parse(transaction.expiresAt) }.getOrElse {
            throw NEXUSSignError.AuthorizationPayloadInvalid("invalid_timestamp", "expires_at")
        }
        if (!Instant.now().isBefore(expiry)) throw NEXUSSignError.AuthorizationExpired
    }

    private fun requireBiometrics(activity: FragmentActivity) {
        when (BiometricManager.from(activity).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)) {
            BiometricManager.BIOMETRIC_SUCCESS -> Unit
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> throw NEXUSSignError.NoAuthenticationMethodEnrolled
            else -> throw NEXUSSignError.BiometryUnavailable
        }
    }

    /**
     * Refuses KDF parameters that would weaken the wrapping key (a malicious or
     * misconfigured server could otherwise request 1 iteration or a short key).
     */
    private fun validated(parameters: NexusRecoveryParameters): ByteArray {
        val salt = runCatching { Base64.getDecoder().decode(parameters.salt) }.getOrNull()
        if (parameters.protocol != RecoveryProtocol.PROTOCOL ||
            parameters.kdf != RecoveryProtocol.KDF ||
            parameters.keyLength != RecoveryProtocol.KEY_LENGTH ||
            parameters.iterations !in RecoveryProtocol.ITERATION_RANGE ||
            salt == null || salt.size < RecoveryProtocol.MIN_SALT_BYTES
        ) {
            throw NEXUSSignError.ServerError(0, "Recovery parameters are outside the supported range")
        }
        return salt
    }

    /**
     * Play Integrity token bound to the challenge and every enrolled key
     * (`challenge || 0x00 || signing PEM || 0x00 || auth PEM || 0x00 || offline PEM`),
     * and the Keystore attestation chains of the signing and authentication
     * keys. When Play Integrity is unavailable or fails, the reason is sent
     * instead and Auth Core applies the bank's policy (production requires
     * attestation).
     */
    private suspend fun attestationPayload(challenge: ByteArray, keys: NetworkClient.EnrolmentKeys): JsonObject {
        val keyAttestation = buildJsonObject {
            put("signingKeyChain", JsonArray(keys.signingAttestation.map { JsonPrimitive(it) }))
            put("authenticationKeyChain", JsonArray(keys.authenticationAttestation.map { JsonPrimitive(it) }))
        }
        if (!attestationProvider.isSupported) return buildJsonObject { put("supported", false); put("keyAttestation", keyAttestation) }
        val zero = byteArrayOf(0)
        val binding = challenge + zero + keys.signing.toByteArray(Charsets.UTF_8) +
            zero + keys.authentication.toByteArray(Charsets.UTF_8) +
            zero + (keys.offline ?: "").toByteArray(Charsets.UTF_8)
        val token = try {
            attestationProvider.requestToken(binding)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            null
        }
        return buildJsonObject {
            put("supported", true)
            if (token != null) put("integrityToken", token) else put("attestationError", "attestation_failed")
            put("keyAttestation", keyAttestation)
        }
    }

    /** Shows the system biometric prompt on the main thread. With [crypto] the
     * prompt unlocks that object for one use; without it, it unlocks keys with
     * a validity window (the offline key). */
    private suspend fun authenticate(activity: FragmentActivity, crypto: BiometricPrompt.CryptoObject?, description: String): BiometricPrompt.AuthenticationResult =
        withContext(Dispatchers.Main) {
            suspendCancellableCoroutine { continuation ->
                val executor = activity.mainExecutor
                val prompt = BiometricPrompt(activity, executor, object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        if (continuation.isActive) continuation.resume(result)
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        if (continuation.isActive) continuation.resumeWithException(biometricError(errorCode, errString))
                    }
                })
                continuation.invokeOnCancellation { executor.execute { prompt.cancelAuthentication() } }
                val promptInfo = BiometricPrompt.PromptInfo.Builder()
                    .setTitle(config.promptTitle)
                    .setDescription(description)
                    .setNegativeButtonText(config.promptCancelText)
                    .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                    .setConfirmationRequired(true)
                    .build()
                if (crypto != null) prompt.authenticate(promptInfo, crypto) else prompt.authenticate(promptInfo)
            }
        }

    private fun biometricError(errorCode: Int, errString: CharSequence): NEXUSSignError = when (errorCode) {
        BiometricPrompt.ERROR_LOCKOUT, BiometricPrompt.ERROR_LOCKOUT_PERMANENT -> NEXUSSignError.BiometryLockedOut
        BiometricPrompt.ERROR_NO_BIOMETRICS -> NEXUSSignError.NoAuthenticationMethodEnrolled
        BiometricPrompt.ERROR_HW_NOT_PRESENT -> NEXUSSignError.BiometryUnavailable
        else -> NEXUSSignError.AuthenticationDenied(errString.toString())
    }

    private companion object {
        val replacementLock = Mutex()
        val pushRegistrationLock = Mutex()
        val UUID_PATTERN = Regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
    }
}
