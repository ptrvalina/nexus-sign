import Foundation
import LocalAuthentication
import Security
import CryptoKit

/// Native SDK embedded in the bank's existing iOS application.
///
/// The host application owns customer login, token issuance and all bank UI.
/// This SDK owns the device credential, transaction signing and the protocol
/// boundary with NEXUS-SIGN Auth Core.
public final class NEXUSSignSDK {
    private let config: NEXUSSignConfig
    private let state: SDKState
    private let keyManager: KeyManager
    private let attestationProvider = AttestationProvider()
    private let networkClient: NetworkClient
    private let offlineSignatures: OfflineSignatureQueue

    public init(config: NEXUSSignConfig) {
        self.config = config
        self.state = SDKState(bankID: config.bankID)
        self.offlineSignatures = OfflineSignatureQueue(bankID: config.bankID)
        self.keyManager = KeyManager(bankID: config.bankID, accessGroup: config.keychainAccessGroup, state: state)
        self.networkClient = NetworkClient(config: config)
        useDeviceAuthentication()
    }

    /// True once Auth Core has confirmed this device's credential (after
    /// `bootstrap()` or `recoverIdentity`) and the key is present.
    public func isRegistered() throws -> Bool {
        try keyManager.effectiveCredentialID != nil && keyManager.existingKey() != nil
    }

    /// The credential ID confirmed by Auth Core, if the device is registered.
    public var credentialID: String? { keyManager.effectiveCredentialID }

    /// Fingerprint of this device's signing key: hex SHA-256 of its DER
    /// SubjectPublicKeyInfo, computed here from the key in the Secure Enclave,
    /// not taken from any Auth Core response. After enrolment, replacement or
    /// recovery the app sends it with the credential ID to the bank's own
    /// backend, which approves exactly this key for the customer
    /// (docs/protocol/bank-credential-trust-v1.md). Nil when not registered.
    public func signingKeyFingerprint() throws -> String? {
        guard try isRegistered(), let info = try keyManager.activeSigningPublicKeyInfo() else { return nil }
        return SubjectPublicKeyInfo.fingerprint(info)
    }

    /// True when this device can confirm transactions from a QR code without network.
    public func isOfflineConfirmationAvailable() throws -> Bool {
        try isRegistered() && keyManager.effectiveOfflineServerPublicKeyPEM != nil && keyManager.existingKey(.offline) != nil
    }

    /// Enrols this device with a BOOTSTRAP token from the host app: generates
    /// the signing, authentication and offline keys in the Secure Enclave and
    /// registers them with one App Attest attestation covering all three.
    /// Afterwards the device signs its own requests and needs no further
    /// token. A customer who already has an enrolled device can only be
    /// enrolled with a replacement token the bank issues after re-identifying
    /// them (Auth Core answers 409 otherwise); if enrolment fails, the
    /// previous keys stay in place.
    public func bootstrap() async throws -> NexusMobileRegistration {
        let bootstrapToken = try await config.sessionToken(.bootstrap)
        let challenge = Data(SHA256.hash(data: Data(bootstrapToken.utf8)))
        let registration: NexusMobileRegistration = try await withReplacementKeys(
            register: { keys in
                let attestation = await self.buildAttestationPayload(challenge: challenge, keys: keys)
                return try await self.networkClient.bootstrap(keys: keys, securityLevel: "SECURE_ENCLAVE",
                                                              attestation: attestation, bootstrapToken: bootstrapToken)
            },
            confirmed: { (credentialID: $0.credentialId, offlineServerPublicKeyPEM: $0.offlineServerPublicKeyPem,
                          deviceSignatures: $0.requestAuthentication == "DEVICE_SIGNATURE") }
        )
        useDeviceAuthentication()
        return registration
    }

    /// Fetches an authorization and verifies that its displayable fields match
    /// the exact bytes the device would sign. Throws
    /// `NEXUSSignError.authorizationPayloadInvalid` if they do not.
    ///
    /// Render the confirmation screen from `authorization.signedTransaction()`,
    /// which holds the values that will be signed.
    public func fetchAuthorization(authorizationID: String) async throws -> NexusAuthorization {
        // The ID may come from a push or deep link: it must not steer the
        // signed request to another endpoint.
        guard UUID(uuidString: authorizationID) != nil else {
            throw NEXUSSignError.authorizationPayloadInvalid(reason: "invalid_id", detail: "authorizationId")
        }
        let authorization = try await networkClient.fetchAuthorization(authorizationID: authorizationID)
        guard authorization.authorizationId == authorizationID else {
            throw NEXUSSignError.authorizationPayloadInvalid(reason: "response_mismatch", detail: "authorizationId")
        }
        _ = try authorization.signedTransaction()
        return authorization
    }

    /// Asks for biometric confirmation showing the signed transaction, signs
    /// the canonical bytes and submits the signature.
    /// Opens an audio or video verification session for `authorization` when
    /// the bank's verification plan asks for one (ADR 0017). The signed bytes
    /// are verified first, so the terms shown during the call
    /// (`signedTransaction().confirmationText`) are those the operator sees
    /// and the device will sign. Auth Core binds the session to this
    /// authorization and this device. At most three sessions per channel.
    ///
    /// Run the call with `callSignalling(for:)` and a media engine
    /// (NEXUSSignCalls). The call never confirms the payment: after a
    /// VERIFIED decision, call `approve(authorization:)` as usual.
    public func openVerificationCall(authorization: NexusAuthorization, channel: VerificationChannel) async throws -> VerificationSession {
        let signed = try authorization.signedTransaction()
        guard let expiry = signed.expiresAtDate, Date() < expiry else { throw NEXUSSignError.authorizationExpired }
        guard let credentialID = keyManager.effectiveCredentialID else { throw NEXUSSignError.notRegistered }
        guard signed.credentialId == credentialID else {
            throw NEXUSSignError.authorizationPayloadInvalid(reason: "wrong_device", detail: "the authorization is for another device")
        }
        let body = try await networkClient.openVerificationSession(authorizationID: authorization.authorizationId, channel: channel)
        return try CallWire.decodeSession(body, authorizationID: authorization.authorizationId)
    }

    /// Device-signed signalling of one verification session.
    public func callSignalling(for session: VerificationSession) throws -> CallSignalling {
        guard keyManager.effectiveCredentialID != nil else { throw NEXUSSignError.notRegistered }
        return DeviceCallSignalling(sessionID: session.sessionID, network: networkClient)
    }

    public func approve(authorization: NexusAuthorization) async throws -> NEXUSVerificationOutcome {
        // Expiry, prompt text and the signed bytes all come from the one
        // verified canonical payload, never from the JSON convenience fields.
        let signed = try authorization.signedTransaction()
        guard let canonicalBytes = Data(base64Encoded: authorization.canonicalPayloadBase64) else {
            throw NEXUSSignError.authorizationPayloadInvalid(reason: "invalid_json", detail: "canonicalPayloadBase64")
        }
        guard let expiry = signed.expiresAtDate, Date() < expiry else { throw NEXUSSignError.authorizationExpired }
        guard let credentialID = keyManager.effectiveCredentialID else { throw NEXUSSignError.notRegistered }
        guard signed.credentialId == credentialID else {
            throw NEXUSSignError.authorizationPayloadInvalid(reason: "wrong_device", detail: "the authorization is for another device")
        }

        let context = LAContext()
        var policyError: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &policyError) else {
            throw Self.biometryError(policyError)
        }
        context.localizedReason = signed.confirmationText
        // The key reference must be fetched with this context for the system
        // prompt to use it (and its localizedReason).
        let signature = try withBiometryCheck {
            guard let privateKey = try keyManager.existingKey(context: context) else { throw NEXUSSignError.notRegistered }
            return try keyManager.sign(payload: canonicalBytes, using: privateKey)
        }
        do {
            return try await networkClient.signAuthorization(authorizationID: signed.authorizationId, signature: signature).status
        } catch NEXUSSignError.serverError(let statusCode, _) where statusCode == 410 {
            throw NEXUSSignError.authorizationExpired
        }
    }

    /// Generates a 12-word recovery phrase and registers a recovery key
    /// wrapped under it (recovery protocol 2). The customer confirms with
    /// biometrics: the registration is signed with this device's signing key,
    /// so a stolen session token alone cannot replace the recovery key. Returns
    /// the words for the customer to write down; neither the phrase nor the
    /// recovery private key leaves the device.
    public func generateRecoveryPhrase() async throws -> [String] {
        guard let credentialID = keyManager.effectiveCredentialID else { throw NEXUSSignError.notRegistered }
        let parameters = try await networkClient.recoveryParameters()
        let salt = try Self.validated(parameters)
        guard let nexusID = parameters.nexusId, parameters.credentialId == credentialID else {
            throw NEXUSSignError.serverError(statusCode: 0, message: "Recovery parameters are for another device")
        }

        let context = LAContext()
        var policyError: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &policyError) else {
            throw Self.biometryError(policyError)
        }
        context.localizedReason = config.recoverySetupPromptText
        let signingKey = try withBiometryCheck { () throws -> SecKey in
            guard let key = try keyManager.existingKey(context: context) else { throw NEXUSSignError.notRegistered }
            return key
        }

        let phrase = try RecoveryPhrase.generate()
        let recoveryKey = P256.Signing.PrivateKey()
        let recoverySPKI = recoveryKey.publicKey.derRepresentation
        var seed = RecoveryProtocol.seed(phrase: phrase, salt: salt, iterations: parameters.iterations)
        defer { seed.resetBytes(in: 0..<seed.count) }
        let wrapKey = RecoveryProtocol.wrapKey(seed: seed, nexusID: nexusID)
        let wrapped = try RecoveryProtocol.wrap(recoveryKey, wrapKey: wrapKey,
                                                associatedData: RecoveryProtocol.associatedData(nexusID: nexusID, recoveryPublicKeySPKI: recoverySPKI))
        let setupInput = RecoveryProtocol.setupSigningInput(nexusID: nexusID, credentialID: credentialID, saltBase64: parameters.salt,
                                                            recoveryPublicKeySPKI: recoverySPKI, wrapped: wrapped)
        let signature = try withBiometryCheck { try keyManager.sign(payload: setupInput, using: signingKey) }
        try await networkClient.configureRecovery(salt: parameters.salt, recoveryPublicKeyPEM: recoveryKey.publicKey.pemRepresentation,
                                                  wrappedRecoveryKey: wrapped, signature: signature)
        return phrase
    }

    /// Recovers the customer's identity on this device with the recovery
    /// phrase. `session` is created by the bank backend after it has
    /// re-identified the customer. A wrong phrase is detected on the device
    /// (the wrapped recovery key does not open) and uses no server attempt.
    public func recoverIdentity(session: NexusRecoverySession, recoveryPhrase: [String]) async throws -> NexusRecoveryResult {
        let words = RecoveryPhrase.normalized(recoveryPhrase)
        guard RecoveryPhrase.isWellFormed(words) else { throw NEXUSSignError.invalidRecoveryPhrase }
        // The session ID comes from the host app and becomes part of the path.
        guard UUID(uuidString: session.sessionId) != nil, let nonce = Data(base64Encoded: session.nonce),
              let recoveryPublicKeyPEM = session.recoveryPublicKeyPem,
              let recoverySPKI = RecoveryProtocol.spki(fromPEM: recoveryPublicKeyPEM),
              let wrapped = session.wrappedRecoveryKey.flatMap({ Data(base64Encoded: $0) }) else {
            throw NEXUSSignError.serverError(statusCode: 0, message: "Invalid recovery session")
        }
        let salt = try Self.validated(session.parameters)
        var seed = RecoveryProtocol.seed(phrase: words, salt: salt, iterations: session.parameters.iterations)
        defer { seed.resetBytes(in: 0..<seed.count) }
        let wrapKey = RecoveryProtocol.wrapKey(seed: seed, nexusID: session.nexusId)
        let recoveryKey = try RecoveryProtocol.unwrap(wrapped, wrapKey: wrapKey,
                                                      associatedData: RecoveryProtocol.associatedData(nexusID: session.nexusId, recoveryPublicKeySPKI: recoverySPKI))
        guard recoveryKey.publicKey.derRepresentation == recoverySPKI else { throw NEXUSSignError.invalidRecoveryPhrase }

        // The replacement keys stay under separate tags until Auth Core
        // confirms the recovery. A network failure or an interrupted call
        // leaves the current keys untouched.
        let result: NexusRecoveryResult
        do {
            result = try await withReplacementKeys(
                register: { keys in
                    guard let newSigningSPKI = RecoveryProtocol.spki(fromPEM: keys.signing) else {
                        throw NEXUSSignError.serverError(statusCode: 0, message: "Invalid signing key")
                    }
                    let proof = try RecoveryProtocol.sign(
                        RecoveryProtocol.proofSigningInput(sessionID: session.sessionId, nonceBase64: session.nonce,
                                                           nexusID: session.nexusId, newSigningKeySPKI: newSigningSPKI),
                        with: recoveryKey)
                    let attestation = await self.buildAttestationPayload(challenge: nonce, keys: keys)
                    return try await self.networkClient.recover(session: session, proof: proof, keys: keys, attestation: attestation)
                },
                confirmed: { (credentialID: $0.credentialId, offlineServerPublicKeyPEM: $0.offlineServerPublicKeyPem,
                              deviceSignatures: $0.requestAuthentication == "DEVICE_SIGNATURE") }
            )
        } catch NEXUSSignError.serverError(let statusCode, _) where statusCode == 401 {
            throw NEXUSSignError.invalidRecoveryPhrase
        }
        useDeviceAuthentication()
        return result
    }

    /// Reads an offline QR code shown by the bank (branch, ATM, web banking)
    /// and verifies it exactly as `fetchAuthorization` verifies an online
    /// authorization. No network is used. Render the confirmation screen from
    /// `challenge.transaction`.
    public func readOfflineChallenge(qrPayload: String) throws -> NexusOfflineChallenge {
        let version = try DeviceProtocol.qrPayloadVersion(qrPayload)
        let bytes = try DeviceProtocol.qrPayloadBytes(qrPayload)
        let transaction: NexusSignedTransaction
        do {
            transaction = try SignedPayload.parse(bytes)
        } catch let rejected as SignedPayload.Rejected {
            throw NEXUSSignError.authorizationPayloadInvalid(reason: rejected.reason, detail: rejected.detail)
        }
        guard transaction.credentialId == keyManager.effectiveCredentialID else {
            throw NEXUSSignError.authorizationPayloadInvalid(reason: "wrong_device", detail: "the QR code is for another device")
        }
        guard let expiry = transaction.expiresAtDate, Date() < expiry else { throw NEXUSSignError.authorizationExpired }
        return NexusOfflineChallenge(transaction: transaction, canonicalPayload: bytes, requiresDeviceSignature: version == 2)
    }

    /// Asks for biometric confirmation showing the transaction and returns the
    /// 8-digit code the customer types on the bank's screen. Works without
    /// network. The code is valid only for this exact transaction.
    ///
    /// Offline confirmation v2 (`challenge.requiresDeviceSignature`): the one
    /// biometric evaluation of the context authorizes the signing key, which
    /// signs the transaction, and the offline key. The signature is stored
    /// before the code is computed. Call `submitPendingOfflineSignatures()`
    /// whenever the app is online; Auth Core confirms the payment when the
    /// signature arrives.
    public func confirmOffline(_ challenge: NexusOfflineChallenge) async throws -> String {
        guard let credentialID = keyManager.effectiveCredentialID else { throw NEXUSSignError.notRegistered }
        guard let serverKey = keyManager.effectiveOfflineServerPublicKeyPEM else { throw NEXUSSignError.offlineConfirmationUnavailable }
        guard let expiry = challenge.transaction.expiresAtDate, Date() < expiry else { throw NEXUSSignError.authorizationExpired }

        let context = LAContext()
        var policyError: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &policyError) else {
            throw Self.biometryError(policyError)
        }
        context.localizedReason = challenge.transaction.confirmationText
        if challenge.requiresDeviceSignature {
            guard UUID(uuidString: challenge.transaction.authorizationId) != nil else {
                throw NEXUSSignError.authorizationPayloadInvalid(reason: "invalid_qr", detail: "authorization ID is not a UUID")
            }
            // Evaluate once; both Secure Enclave keys are then used with this
            // already-evaluated context, without a second prompt.
            do {
                _ = try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: challenge.transaction.confirmationText)
            } catch {
                throw NEXUSSignError.authenticationDenied
            }
            let signature = try withBiometryCheck {
                guard let privateKey = try keyManager.existingKey(context: context) else { throw NEXUSSignError.notRegistered }
                return try keyManager.sign(payload: challenge.canonicalPayload, using: privateKey)
            }
            // Stored before the code exists: no code without its signature.
            try offlineSignatures.add(authorizationID: challenge.transaction.authorizationId, signature: signature)
        }
        // The key agreement itself shows the biometric prompt of `context`
        // (v1); in v2 the context is already evaluated.
        var shared = try withBiometryCheck { try keyManager.offlineSharedSecret(serverPublicKeyPEM: serverKey, context: context) }
        defer { shared.resetBytes(in: 0..<shared.count) }
        let key = DeviceProtocol.deriveOfflineKey(sharedSecret: shared, credentialID: credentialID)
        return DeviceProtocol.offlineCode(tag: DeviceProtocol.offlineTag(key: key, canonicalPayload: challenge.canonicalPayload))
    }

    /// Offline confirmation v2: uploads the signatures made by
    /// `confirmOffline` that Auth Core does not have yet. Call it when the app
    /// starts and whenever it regains a connection. Signatures Auth Core
    /// accepted, or can never accept, are removed; the others are kept.
    @discardableResult
    public func submitPendingOfflineSignatures() async -> OfflineSignatureDelivery {
        guard keyManager.effectiveCredentialID != nil else {
            return OfflineSignatureDelivery(delivered: 0, refused: 0, pending: offlineSignatures.pending().count)
        }
        return await offlineSignatures.deliver { item in
            guard UUID(uuidString: item.authorizationId) != nil else { return .refused(statusCode: 0) }
            do {
                try await networkClient.uploadDeferredSignature(authorizationID: item.authorizationId, signatureBase64: item.signature)
                return .accepted
            } catch NEXUSSignError.serverError(let statusCode, _) {
                return UploadOutcome.of(statusCode: statusCode)
            } catch {
                return .retry
            }
        }
    }

    // MARK: - Secure push (bank push mode NEXUS)

    /// Registers this device for NEXUS-SIGN secure push with the APNs token
    /// from `application(_:didRegisterForRemoteNotificationsWithDeviceToken:)`.
    /// Call it at every launch and whenever the token changes, and after
    /// `bootstrap()` or recovery: a new credential agrees a new push key.
    public func registerPush(deviceToken: Data, environment: NexusAPNsEnvironment = .production) async throws {
        // One registration at a time: two concurrent agreements could leave
        // the device with a different key from Auth Core's.
        await Self.pushRegistrationGate.enter()
        do {
            try await registerPushSerialized(deviceToken: deviceToken, environment: environment)
            await Self.pushRegistrationGate.leave()
        } catch {
            await Self.pushRegistrationGate.leave()
            throw error
        }
    }

    private static let pushRegistrationGate = ReplacementGate()

    private func registerPushSerialized(deviceToken: Data, environment: NexusAPNsEnvironment) async throws {
        guard let credentialID = keyManager.effectiveCredentialID else { throw NEXUSSignError.notRegistered }
        let token = deviceToken.map { String(format: "%02x", $0) }.joined()
        let store = PushKeyStore(bankID: config.bankID, accessGroup: config.pushKeychainAccessGroup)

        if let existing = try store.load(credentialID: credentialID) {
            do {
                _ = try await networkClient.registerPush(deviceToken: token, environment: environment,
                                                         devicePublicKeyPEM: nil, keyID: PushProtocol.keyID(existing))
                return
            } catch NEXUSSignError.serverError(let statusCode, _) where statusCode == 409 {
                // Auth Core holds another key (or none) for this device: agree a new one.
            }
        }

        // An agreement whose answer is lost must not leave a stale key behind.
        store.delete()
        // Ephemeral key pair, in memory only; the agreed key is all that is kept.
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let response = try await networkClient.registerPush(
            deviceToken: token, environment: environment,
            devicePublicKeyPEM: SubjectPublicKeyInfo.pem(fromRawECPoint: ephemeral.publicKey.x963Representation), keyID: nil)
        guard let serverPEM = response.serverPublicKeyPem,
              let serverKey = try? P256.KeyAgreement.PublicKey(pemRepresentation: serverPEM) else {
            throw NEXUSSignError.serverError(statusCode: 200, message: "Auth Core returned no push key agreement")
        }
        var shared = try ephemeral.sharedSecretFromKeyAgreement(with: serverKey).withUnsafeBytes { Data($0) }
        defer { shared.resetBytes(in: 0..<shared.count) }
        let key = PushProtocol.derivePushKey(sharedSecret: shared, credentialID: credentialID)
        guard PushProtocol.keyID(key) == response.keyId else {
            throw NEXUSSignError.serverError(statusCode: 200, message: "Push key agreement did not match")
        }
        try store.save(key, credentialID: credentialID)
    }

    /// Stops secure push to this device and deletes its push key.
    public func unregisterPush() async throws {
        // The local push key goes even when Auth Core cannot be told (offline,
        // or a device that can no longer sign requests).
        defer { PushKeyStore(bankID: config.bankID, accessGroup: config.pushKeychainAccessGroup).delete() }
        try await networkClient.unregisterPush()
    }

    /// Opens a secure push the app received (in the foreground, or when the
    /// customer tapped the notification). Returns `nil` for other notifications.
    public func openPush(userInfo: [AnyHashable: Any]) throws -> NexusPushMessage? {
        let reader = NEXUSSignPushReader(bankID: config.bankID, keychainAccessGroup: config.pushKeychainAccessGroup)
        guard reader.isSecurePush(userInfo) else { return nil }
        return try reader.open(userInfo: userInfo)
    }

    /// Fetches and opens a message by ID, for when the app opens before the
    /// push arrives (or it never arrived).
    public func fetchPushMessage(messageID: String) async throws -> NexusPushMessage {
        guard UUID(uuidString: messageID) != nil else { throw NEXUSSignError.pushMessageInvalid(reason: "malformed_envelope") }
        let response = try await networkClient.fetchPushEnvelope(messageID: messageID)
        guard response.envelope.id == messageID, response.envelope.cid == keyManager.effectiveCredentialID else {
            throw NEXUSSignError.pushMessageInvalid(reason: "malformed_envelope")
        }
        return try NEXUSSignPushReader(bankID: config.bankID, keychainAccessGroup: config.pushKeychainAccessGroup).open(response.envelope)
    }

    /// Confirms to Auth Core that the message reached the customer; the bank
    /// receives push.delivered. The notification extension can send the same
    /// receipt with `NEXUSSignPushReader.sendReceipt`.
    public func confirmPushReceipt(_ message: NexusPushMessage) async throws {
        try await NEXUSSignPushReader(bankID: config.bankID, keychainAccessGroup: config.pushKeychainAccessGroup)
            .sendReceipt(for: message, baseURL: config.baseURL, timeout: config.requestTimeout)
    }

    // MARK: - Decline

    /// The customer refuses the payment instead of confirming it. The bank
    /// receives `authorization.declined` with the reason; the authorization
    /// can no longer be confirmed.
    public func decline(authorization: NexusAuthorization, reason: NexusDeclineReason) async throws {
        try await networkClient.declineAuthorization(authorizationID: authorization.authorizationId, reason: reason)
    }

    // MARK: - Device replacement

    /// Open device replacements the bank requested for this NEXUS ID. Show
    /// them to the customer on this (enrolled) device.
    public func pendingDeviceReplacements() async throws -> [NexusDeviceReplacement] {
        try await networkClient.deviceReplacements()
    }

    /// The customer confirms the replacement: the new device can be enrolled
    /// now instead of after the hold. After enrolment this device is revoked.
    public func approveDeviceReplacement(replacementID: String) async throws -> NexusDeviceReplacement {
        guard UUID(uuidString: replacementID) != nil else { throw NEXUSSignError.serverError(statusCode: 400, message: "Malformed replacement ID") }
        return try await networkClient.decideDeviceReplacement(replacementID: replacementID, approve: true)
    }

    /// The customer refuses the replacement ("it wasn't me"); it can never be used.
    public func cancelDeviceReplacement(replacementID: String) async throws -> NexusDeviceReplacement {
        guard UUID(uuidString: replacementID) != nil else { throw NEXUSSignError.serverError(statusCode: 400, message: "Malformed replacement ID") }
        return try await networkClient.decideDeviceReplacement(replacementID: replacementID, approve: false)
    }

    // MARK: - Helpers

    /// Runs a biometry-bound key operation; when it fails because the
    /// biometric enrolment changed since the device was enrolled, reports
    /// `.credentialInvalidated` instead of a missing key or a denied prompt.
    private func withBiometryCheck<T>(_ operation: () throws -> T) throws -> T {
        do {
            return try operation()
        } catch NEXUSSignError.notRegistered where keyManager.effectiveCredentialID != nil && keyManager.biometryChangedSinceEnrolment {
            throw NEXUSSignError.credentialInvalidated
        } catch NEXUSSignError.offlineConfirmationUnavailable where keyManager.effectiveCredentialID != nil && keyManager.biometryChangedSinceEnrolment {
            throw NEXUSSignError.credentialInvalidated
        } catch NEXUSSignError.authenticationDenied where keyManager.biometryChangedSinceEnrolment {
            throw NEXUSSignError.credentialInvalidated
        }
    }

    /// Refuses parameters that would weaken the wrapping key (a malicious or
    /// misconfigured server could otherwise request 1 iteration or an empty
    /// salt) and any protocol other than 2.
    private static func validated(_ parameters: NexusRecoveryParameters) throws -> Data {
        guard parameters.protocolVersion == RecoveryProtocol.version,
              parameters.kdf == RecoveryProtocol.kdf,
              parameters.keyLength == RecoveryProtocol.keyLength,
              (100_000...5_000_000).contains(parameters.iterations),
              let salt = Data(base64Encoded: parameters.salt), salt.count >= 16 else {
            throw NEXUSSignError.serverError(statusCode: 0, message: "Recovery parameters are outside the supported range")
        }
        return salt
    }

    private static func biometryError(_ error: NSError?) -> NEXUSSignError {
        switch (error as? LAError)?.code {
        case .biometryLockout?: return .biometryLockedOut
        case .biometryNotAvailable?: return .biometryUnavailable
        default: return .noAuthenticationMethodEnrolled
        }
    }

    /// Runs one enrolment or recovery attempt with a fresh key set: promotes
    /// the new keys together with the `confirmed` registration only if
    /// `register` succeeds, discards them otherwise.
    private func withReplacementKeys<T>(
        register: (NetworkClient.EnrolmentKeys) async throws -> T,
        confirmed: (T) -> (credentialID: String, offlineServerPublicKeyPEM: String?, deviceSignatures: Bool)
    ) async throws -> T {
        // One attempt at a time per process: two attempts would share the
        // replacement tags, and the second would delete the first's keys.
        await Self.replacementGate.enter()
        do {
            let result = try await replaceKeys(register: register, confirmed: confirmed)
            await Self.replacementGate.leave()
            return result
        } catch {
            await Self.replacementGate.leave()
            throw error
        }
    }

    private static let replacementGate = ReplacementGate()

    private func replaceKeys<T>(
        register: (NetworkClient.EnrolmentKeys) async throws -> T,
        confirmed: (T) -> (credentialID: String, offlineServerPublicKeyPEM: String?, deviceSignatures: Bool)
    ) async throws -> T {
        let prepared = try keyManager.prepareReplacementKeys()
        let result: T
        do {
            let keys = NetworkClient.EnrolmentKeys(
                signing: try keyManager.publicKeyPEM(for: prepared.signing),
                authentication: try keyManager.publicKeyPEM(for: prepared.authentication),
                offline: try keyManager.publicKeyPEM(for: prepared.offline)
            )
            result = try await register(keys)
        } catch {
            keyManager.discardReplacementKeys()
            throw error
        }
        let registration = confirmed(result)
        keyManager.commitReplacementKeys(credentialID: registration.credentialID,
                                         offlineServerPublicKeyPEM: registration.offlineServerPublicKeyPEM,
                                         deviceSignatures: registration.deviceSignatures)
        return result
    }

    /// Signs every device request with the authentication key of the
    /// enrolled credential. Without one (an enrolment from SDK 1.1 or
    /// earlier) requests fail with `notRegistered`, and the device must be
    /// enrolled again through a replacement.
    private func useDeviceAuthentication() {
        let keyManager = self.keyManager
        let hasAuthenticationKey = (try? keyManager.existingKey(.authentication)) != nil
        if let credentialID = keyManager.effectiveCredentialID, hasAuthenticationKey, keyManager.effectiveDeviceSignatures {
            networkClient.deviceIdentity = NetworkClient.DeviceIdentity(credentialID: credentialID) { input in
                try keyManager.signRequest(input)
            }
        } else {
            networkClient.deviceIdentity = nil
        }
    }

    /// App Attest evidence for the challenge and every enrolled key:
    /// `challenge || 0x00 || signing PEM || 0x00 || auth PEM || 0x00 || offline PEM`.
    /// When attestation is unavailable or fails, the reason is sent instead
    /// and Auth Core applies the bank's policy (production requires it).
    private func buildAttestationPayload(challenge: Data, keys: NetworkClient.EnrolmentKeys) async -> [String: Any] {
        var binding = challenge
        binding.append(0); binding.append(Data(keys.signing.utf8))
        binding.append(0); binding.append(Data(keys.authentication.utf8))
        binding.append(0); binding.append(Data(keys.offline.utf8))
        guard attestationProvider.isSupported else { return ["supported": false] }
        do {
            let keyID = try await attestationProvider.generateAttestationKey()
            let object = try await attestationProvider.attest(keyID: keyID, clientData: binding)
            return ["supported": true, "keyId": keyID, "attestationObject": object.base64EncodedString()]
        } catch {
            return ["supported": true, "attestationError": "attestation_failed"]
        }
    }
}

/// Admits one key replacement (enrolment or recovery) at a time; later
/// callers wait in order.
private actor ReplacementGate {
    private var busy = false
    private var waiting: [CheckedContinuation<Void, Never>] = []

    func enter() async {
        guard busy else {
            busy = true
            return
        }
        await withCheckedContinuation { continuation in
            waiting.append(continuation)
        }
    }

    func leave() {
        if waiting.isEmpty {
            busy = false
        } else {
            waiting.removeFirst().resume()
        }
    }
}

// MARK: - Customer section, payment mandates, conversations with the bank

extension NEXUSSignSDK {

    private static func checkedID(_ value: String, _ what: String) throws -> String {
        guard UUID(uuidString: value) != nil else { throw NEXUSSignError.serverError(statusCode: 400, message: "Malformed \(what)") }
        return value.lowercased()
    }

    /// The customer's devices ("My devices"), this one marked `thisDevice`.
    public func devices() async throws -> [NexusDevice] {
        let list: DeviceList = try await networkClient.deviceCall("GET", "/v1/mobile/devices")
        return list.devices
    }

    /// Removes one of the customer's devices (another one, or this one).
    /// Returns how many active devices remain.
    public func removeDevice(credentialID: String) async throws -> Int {
        let id = try Self.checkedID(credentialID, "credential ID")
        let result: DeviceRevoked = try await networkClient.deviceCall("POST", "/v1/mobile/devices/\(id)/revoke", body: [:])
        return result.remainingActiveDevices
    }

    /// Payments confirmed, declined or open, newest first.
    public func history(filter: NexusHistoryFilter = .all, before: String? = nil, limit: Int = 50) async throws -> [NexusHistoryEntry] {
        var query = "filter=\(filter.rawValue)&limit=\(max(1, min(limit, 200)))"
        if let before, let encoded = before.addingPercentEncoding(withAllowedCharacters: .alphanumerics) { query += "&before=\(encoded)" }
        let list: HistoryList = try await networkClient.deviceCall("GET", "/v1/mobile/history?\(query)")
        return list.authorizations
    }

    /// The sealed evidence of one of the customer's payments, as JSON the bank's
    /// app can show or hand to the customer; verify it with verify-evidence.
    public func evidence(authorizationID: String) async throws -> Data {
        let id = try Self.checkedID(authorizationID, "authorization ID")
        let object: [String: AnyDecodable] = try await networkClient.deviceCall("GET", "/v1/mobile/authorizations/\(id)/evidence")
        return try JSONSerialization.data(withJSONObject: object.mapValues { $0.value }, options: [.sortedKeys])
    }

    public func securityEvents(limit: Int = 50) async throws -> [NexusSecurityEvent] {
        let list: SecurityEventList = try await networkClient.deviceCall("GET", "/v1/mobile/security-events?limit=\(max(1, min(limit, 200)))")
        return list.events
    }

    public func notifications(limit: Int = 50) async throws -> [NexusNotification] {
        let list: NotificationList = try await networkClient.deviceCall("GET", "/v1/mobile/notifications?limit=\(max(1, min(limit, 200)))")
        return list.notifications
    }

    public func settings() async throws -> NexusCustomerSettings {
        try await networkClient.deviceCall("GET", "/v1/mobile/settings")
    }

    /// Sets limits (minor units, nil for none), the video-check threshold and
    /// channels. A relaxing change takes effect after the bank's hold: read
    /// `effectiveAt` of the result.
    public func updateSettings(currency: String?, perPaymentLimitMinor: String?, dailyLimitMinor: String?, videoCheckAboveMinor: String?, channels: NexusChannels) async throws -> NexusCustomerSettings {
        let body: [String: Any] = [
            "currency": currency as Any? ?? NSNull(), "perPaymentLimitMinor": perPaymentLimitMinor as Any? ?? NSNull(),
            "dailyLimitMinor": dailyLimitMinor as Any? ?? NSNull(), "videoCheckAboveMinor": videoCheckAboveMinor as Any? ?? NSNull(),
            "channels": ["push": channels.push, "audio": channels.audio, "video": channels.video],
        ]
        return try await networkClient.deviceCall("PUT", "/v1/mobile/settings", body: body)
    }

    /// The customer suspends their NEXUS ID; open payments are cancelled and
    /// only the bank can reactivate it after identifying the customer.
    public func suspendIdentity(reason: NexusSuspendReason) async throws {
        let _: [String: String] = try await networkClient.deviceCall("POST", "/v1/mobile/identity/suspend", body: ["reason": reason.rawValue])
    }

    // MARK: Payment mandates

    public func mandates() async throws -> [NexusMandate] {
        let list: MandateList = try await networkClient.deviceCall("GET", "/v1/mobile/mandates")
        return list.mandates
    }

    public func mandate(id: String) async throws -> NexusMandate {
        try await networkClient.deviceCall("GET", "/v1/mobile/mandates/\(try Self.checkedID(id, "mandate ID"))")
    }

    /// Parses and checks the signed terms: domain NEXUS-SIGN/MANDATE (never
    /// payment bytes), this mandate, this identity and this device, display
    /// rules on every shown value, SHA-256 equal to termsHash.
    public func mandateTerms(_ mandate: NexusMandate) throws -> NexusMandateTerms {
        func invalid(_ reason: String, _ detail: String) -> NEXUSSignError { .authorizationPayloadInvalid(reason: reason, detail: detail) }
        guard let bytes = Data(base64Encoded: mandate.termsBase64) else { throw invalid("invalid_json", "termsBase64") }
        guard SHA256.hash(data: bytes).map({ String(format: "%02x", $0) }).joined() == mandate.termsHash else { throw invalid("hash_mismatch", "termsHash") }
        guard let o = (try? JSONSerialization.jsonObject(with: bytes)) as? [String: Any] else { throw invalid("invalid_json", "terms") }
        guard o["domain"] as? String == "NEXUS-SIGN/MANDATE", o["protocol_version"] as? String == "1" else { throw invalid("wrong_domain", "not mandate terms") }
        guard o["mandate_id"] as? String == mandate.mandateId else { throw invalid("mismatch", "mandate_id") }
        guard let credentialID = keyManager.effectiveCredentialID, o["credential_id"] as? String == credentialID else { throw invalid("wrong_device", "the mandate is for another device") }
        func text(_ key: String) throws -> String {
            guard let v = o[key] as? String, SignedPayload.displayTextViolation(v) == nil || ["valid_from", "valid_until", "offer_expires_at"].contains(key) else { throw invalid("display", key) }
            return v
        }
        guard let payee = o["payee"] as? [String: String], !payee.isEmpty, payee.values.allSatisfy({ SignedPayload.displayTextViolation($0) == nil }) else { throw invalid("display", "payee") }
        if let iban = payee["iban"], !SignedPayload.isValidIBAN(iban) { throw invalid("iban", "payee.iban") }
        let total: String?
        if o["total_limit_minor"] is NSNull { total = nil } else { total = try text("total_limit_minor") }
        return NexusMandateTerms(
            mandateId: mandate.mandateId, nexusId: try text("nexus_id"), credentialId: credentialID, mandateReference: try text("mandate_reference"),
            payee: payee, currency: try text("currency"), perPaymentLimitMinor: try text("per_payment_limit_minor"), totalLimitMinor: total,
            frequency: try text("frequency"), validFrom: try text("valid_from"), validUntil: try text("valid_until"),
            termsVersion: try text("terms_version"), offerExpiresAt: try text("offer_expires_at"))
    }

    /// Signs the mandate after biometric authentication, with the prompt built
    /// from the signed terms. Show `mandateTerms(_:)` to the customer first.
    public func signMandate(_ mandate: NexusMandate) async throws -> NexusMandate {
        let terms = try mandateTerms(mandate)
        guard let bytes = Data(base64Encoded: mandate.termsBase64) else { throw NEXUSSignError.authorizationPayloadInvalid(reason: "invalid_json", detail: "termsBase64") }
        let context = LAContext()
        var policyError: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &policyError) else { throw Self.biometryError(policyError) }
        context.localizedReason = terms.confirmationText
        let signature = try withBiometryCheck {
            guard let privateKey = try keyManager.existingKey(context: context) else { throw NEXUSSignError.notRegistered }
            return try keyManager.sign(payload: bytes, using: privateKey)
        }
        return try await networkClient.deviceCall("POST", "/v1/mobile/mandates/\(mandate.mandateId)/signature",
                                                  body: ["signature": signature.base64EncodedString(), "signatureFormat": "der"])
    }

    public enum MandateAction: String { case decline, suspend, resume, revoke }

    public func mandate(id: String, action: MandateAction) async throws -> NexusMandate {
        try await networkClient.deviceCall("POST", "/v1/mobile/mandates/\(try Self.checkedID(id, "mandate ID"))/\(action.rawValue)", body: [:])
    }

    // MARK: Conversations with the bank

    public func conversations() async throws -> [NexusConversation] {
        let list: ConversationList = try await networkClient.deviceCall("GET", "/v1/mobile/conversations")
        return list.conversations
    }

    /// Opens a conversation, optionally about one of the customer's payments.
    /// `clientMessageID` makes a retry safe.
    public func openConversation(topic: String, message: String, authorizationID: String? = nil, attachment: NexusConversationAttachment? = nil,
                                 clientMessageID: String = UUID().uuidString) async throws -> (NexusConversation, NexusConversationMessage) {
        var body: [String: Any] = ["topic": topic, "body": message, "clientMessageId": clientMessageID]
        if let authorizationID { body["authorizationId"] = try Self.checkedID(authorizationID, "authorization ID") }
        if let attachment { body["attachment"] = Self.attachmentJSON(attachment) }
        let opened: ConversationOpened = try await networkClient.deviceCall("POST", "/v1/mobile/conversations", body: body)
        return (opened.conversation, opened.message)
    }

    /// Messages after `after` (0 for the whole history); the bank's messages are marked delivered.
    public func conversationMessages(conversationID: String, after: Int = 0) async throws -> (NexusConversation, [NexusConversationMessage]) {
        let thread: ConversationThread = try await networkClient.deviceCall("GET", "/v1/mobile/conversations/\(try Self.checkedID(conversationID, "conversation ID"))/messages?after=\(max(0, after))")
        return (thread.conversation, thread.messages)
    }

    public func sendMessage(conversationID: String, text: String, attachment: NexusConversationAttachment? = nil, clientMessageID: String = UUID().uuidString) async throws -> NexusConversationMessage {
        var body: [String: Any] = ["body": text, "clientMessageId": clientMessageID]
        if let attachment { body["attachment"] = Self.attachmentJSON(attachment) }
        let sent: MessageSent = try await networkClient.deviceCall("POST", "/v1/mobile/conversations/\(try Self.checkedID(conversationID, "conversation ID"))/messages", body: body)
        return sent.message
    }

    public func markRead(conversationID: String, upToSequence: Int) async throws {
        let _: [String: Int] = try await networkClient.deviceCall("POST", "/v1/mobile/conversations/\(try Self.checkedID(conversationID, "conversation ID"))/read", body: ["upToSequence": upToSequence])
    }

    /// "Talk to a person": the conversation waits for an operator of the bank.
    public func requestAgent(conversationID: String) async throws -> NexusConversation {
        try await networkClient.deviceCall("POST", "/v1/mobile/conversations/\(try Self.checkedID(conversationID, "conversation ID"))/handover", body: [:])
    }

    public func closeConversation(conversationID: String) async throws -> NexusConversation {
        try await networkClient.deviceCall("POST", "/v1/mobile/conversations/\(try Self.checkedID(conversationID, "conversation ID"))/close", body: [:])
    }

    private static func attachmentJSON(_ a: NexusConversationAttachment) -> [String: Any] {
        ["reference": a.reference, "sha256": a.sha256, "mediaType": a.mediaType, "fileName": a.fileName, "sizeBytes": a.sizeBytes]
    }
}

/// Decodes any JSON value (for passing evidence through unchanged).
struct AnyDecodable: Decodable {
    let value: Any
    init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() { value = NSNull() }
        else if let b = try? c.decode(Bool.self) { value = b }
        else if let i = try? c.decode(Int64.self) { value = i }
        else if let d = try? c.decode(Double.self) { value = d }
        else if let s = try? c.decode(String.self) { value = s }
        else if let a = try? c.decode([AnyDecodable].self) { value = a.map { $0.value } }
        else { value = try c.decode([String: AnyDecodable].self).mapValues { $0.value } }
    }
}
