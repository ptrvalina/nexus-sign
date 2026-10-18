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
