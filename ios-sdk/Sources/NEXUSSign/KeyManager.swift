import Foundation
import Security
import LocalAuthentication

/// Owns the device's keys, all P-256 keys generated inside the Secure Enclave
/// and never exportable:
///
/// | Key | Use | Unlock |
/// |---|---|---|
/// | signing | signs the canonical authorization bytes | biometric, every use |
/// | authentication | signs each request to Auth Core | none (device must be unlocked) |
/// | offline | ECDH for offline confirmation codes | biometric, every use |
///
/// Enrolment and recovery generate a new set under separate "replacement"
/// tags and promote it only after Auth Core confirms, so a failed attempt
/// never destroys a working credential.
final class KeyManager {

    enum Kind: CaseIterable {
        case signing, authentication, offline

        fileprivate var suffix: String {
            switch self {
            case .signing: return "signingKey"
            case .authentication: return "authKey"
            case .offline: return "offlineKey"
            }
        }
    }

    struct DeviceKeySet {
        let signing: SecKey
        let authentication: SecKey
        let offline: SecKey
    }

    private let bankID: String
    private let accessGroup: String?
    private let state: SDKState
    /// Serializes key promotion: request signing runs on concurrent tasks.
    private let commitLock = NSLock()

    init(bankID: String, accessGroup: String?, state: SDKState) {
        self.bankID = bankID
        self.accessGroup = accessGroup
        self.state = state
    }

    /// Namespaced per bank so two configurations never collide on a tag.
    private func activeTag(_ kind: Kind) -> Data {
        Data("com.nexis.nexussign.\(bankID).\(kind.suffix)".utf8)
    }

    private func replacementTag(_ kind: Kind) -> Data {
        Data("com.nexis.nexussign.\(bankID).\(kind.suffix).recovery".utf8)
    }

    private func keyQuery(tag: Data) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        ]
        if let accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        return query
    }

    private func copyKey(tag: Data, context: LAContext?) throws -> SecKey? {
        var query = keyQuery(tag: tag)
        query[kSecReturnRef as String] = true
        if let context {
            // Binds the biometric prompt to this context, so its
            // localizedReason (the transaction) is what the system displays.
            query[kSecUseAuthenticationContext as String] = context
        }

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        switch status {
        case errSecSuccess:
            // swiftlint:disable:next force_cast
            return (item as! SecKey)
        case errSecItemNotFound:
            return nil
        default:
            throw NEXUSSignError.keyOperationFailed(status: status)
        }
    }

    /// The active key of `kind`, or `nil` if there is none.
    ///
    /// When Auth Core has confirmed a replacement (`replacementCommitPending`) and
    /// the app stopped before the re-tag completed, the promotion is finished
    /// here. An unconfirmed replacement key is never used.
    func existingKey(_ kind: Kind = .signing, context: LAContext? = nil) throws -> SecKey? {
        if state.replacementCommitPending { try? finishPendingCommit() }
        // A promotion that is still pending is retried later. Meanwhile the
        // confirmed replacement key belongs to the credential in use, so it
        // takes precedence; a key already re-tagged is found under the active tag.
        if state.replacementCommitPending, let key = try copyKey(tag: replacementTag(kind), context: context) {
            return key
        }
        return try copyKey(tag: activeTag(kind), context: context)
    }

    // MARK: - Enrolment and recovery (two-phase)

    /// Step 1: a fresh key set under the replacement tags. The active keys are
    /// left untouched, so a failed or interrupted attempt never destroys a
    /// credential that may still be valid.
    func prepareReplacementKeys() throws -> DeviceKeySet {
        if state.replacementCommitPending { try finishPendingCommit() }
        discardReplacementKeys() // left over from an earlier, interrupted attempt
        do {
            return DeviceKeySet(
                signing: try generateKey(tag: replacementTag(.signing), flags: [.privateKeyUsage, .biometryCurrentSet]),
                authentication: try generateKey(tag: replacementTag(.authentication), flags: [.privateKeyUsage]),
                offline: try generateKey(tag: replacementTag(.offline), flags: [.privateKeyUsage, .biometryCurrentSet])
            )
        } catch {
            discardReplacementKeys()
            throw error
        }
    }

    /// Step 2a (Auth Core confirmed): record the confirmation and the new
    /// registration durably, then replace the active keys with the new set.
    /// The registration is applied together with the re-tag, so the device
    /// never signs with new keys under an old credential ID or the reverse.
    func commitReplacementKeys(credentialID: String, offlineServerPublicKeyPEM: String?, deviceSignatures: Bool) {
        state.pendingCredentialID = credentialID
        state.pendingOfflineServerPublicKeyPEM = offlineServerPublicKeyPEM
        state.pendingDeviceSignatures = deviceSignatures
        state.biometryDomainState = Self.currentBiometryDomainState()
        state.replacementCommitPending = true
        // Auth Core has already switched to the new keys. If the re-tag fails
        // now, the marker makes existingKey() use the replacement keys and
        // retry the promotion, and the effective* values below match them.
        try? finishPendingCommit()
    }

    /// The current biometric enrolment fingerprint (opaque; changes when a
    /// finger or face is added or removed).
    static func currentBiometryDomainState() -> Data? {
        let context = LAContext()
        var error: NSError?
        _ = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
        return context.evaluatedPolicyDomainState
    }

    /// True when the biometric enrolment differs from the one the active keys
    /// were created under, i.e. `.biometryCurrentSet` has invalidated them.
    var biometryChangedSinceEnrolment: Bool {
        guard let enrolled = state.biometryDomainState, let current = Self.currentBiometryDomainState() else { return false }
        return enrolled != current
    }

    /// The credential ID that belongs to the keys `existingKey` returns,
    /// including while a confirmed promotion is still pending.
    var effectiveCredentialID: String? {
        state.replacementCommitPending ? (state.pendingCredentialID ?? state.registeredCredentialID) : state.registeredCredentialID
    }

    var effectiveOfflineServerPublicKeyPEM: String? {
        state.replacementCommitPending && state.pendingCredentialID != nil ? state.pendingOfflineServerPublicKeyPEM : state.offlineServerPublicKeyPEM
    }

    var effectiveDeviceSignatures: Bool {
        state.replacementCommitPending && state.pendingCredentialID != nil ? state.pendingDeviceSignatures : state.deviceSignatures
    }

    /// Step 2b (attempt failed): discard the new set.
    func discardReplacementKeys() {
        for kind in Kind.allCases {
            SecItemDelete(keyQuery(tag: replacementTag(kind)) as CFDictionary)
        }
    }

    private func finishPendingCommit() throws {
        commitLock.lock()
        defer { commitLock.unlock() }
        guard state.replacementCommitPending else { return } // finished by another task
        for kind in Kind.allCases {
            guard try copyKey(tag: replacementTag(kind), context: nil) != nil else { continue } // already promoted
            let deleted = SecItemDelete(keyQuery(tag: activeTag(kind)) as CFDictionary)
            guard deleted == errSecSuccess || deleted == errSecItemNotFound else {
                throw NEXUSSignError.keyOperationFailed(status: deleted)
            }
            let update: [String: Any] = [kSecAttrApplicationTag as String: activeTag(kind)]
            let status = SecItemUpdate(keyQuery(tag: replacementTag(kind)) as CFDictionary, update as CFDictionary)
            guard status == errSecSuccess else {
                // The marker stays set, so existingKey() keeps using the
                // confirmed replacement key and retries the promotion later.
                throw NEXUSSignError.keyOperationFailed(status: status)
            }
        }
        if let credentialID = state.pendingCredentialID {
            state.registeredCredentialID = credentialID
            state.offlineServerPublicKeyPEM = state.pendingOfflineServerPublicKeyPEM
            state.deviceSignatures = state.pendingDeviceSignatures
        }
        state.pendingCredentialID = nil
        state.pendingOfflineServerPublicKeyPEM = nil
        state.replacementCommitPending = false
    }

    /// Generates a P-256 key in the Secure Enclave. `.biometryCurrentSet`
    /// requires a biometric check for every use and invalidates the key if the
    /// enrolled biometrics change, so someone who adds their own fingerprint
    /// to a device cannot use it.
    ///
    /// Throws `.secureEnclaveUnavailable` on devices without a Secure Enclave,
    /// including the simulator.
    private func generateKey(tag: Data, flags: SecAccessControlCreateFlags) throws -> SecKey {
        guard SecureEnclaveSupport.isAvailable else {
            throw NEXUSSignError.secureEnclaveUnavailable
        }

        var accessControlError: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            // Requires a device passcode: without one, "unlocked" is always
            // true and the authentication key would need no user at all. The
            // keys are deleted if the passcode is removed (NXS-027).
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            flags,
            &accessControlError
        ) else {
            let status = (accessControlError?.takeRetainedValue() as Error? as NSError?)?.code ?? Int(errSecParam)
            throw NEXUSSignError.keyOperationFailed(status: OSStatus(status))
        }

        var privateKeyAttrs: [String: Any] = [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: tag,
            kSecAttrAccessControl as String: accessControl,
        ]
        if let accessGroup {
            privateKeyAttrs[kSecAttrAccessGroup as String] = accessGroup
        }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: privateKeyAttrs,
        ]

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            let status = (error?.takeRetainedValue() as Error? as NSError?)?.code ?? Int(errSecParam)
            throw NEXUSSignError.keyOperationFailed(status: OSStatus(status))
        }
        return privateKey
    }

    // MARK: - Use

    /// SPKI PEM of the public half, as Auth Core expects.
    func publicKeyPEM(for privateKey: SecKey) throws -> String {
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw NEXUSSignError.keyOperationFailed(status: errSecParam)
        }
        var error: Unmanaged<CFError>?
        guard let representation = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            let status = (error?.takeRetainedValue() as Error? as NSError?)?.code ?? Int(errSecParam)
            throw NEXUSSignError.keyOperationFailed(status: OSStatus(status))
        }
        return SubjectPublicKeyInfo.pem(fromRawECPoint: representation)
    }

    /// ECDSA over SHA-256 of `payload`, DER-encoded. For the signing key this
    /// shows the biometric prompt of the context the key was fetched with.
    func sign(payload: Data, using privateKey: SecKey) throws -> Data {
        let algorithm: SecKeyAlgorithm = .ecdsaSignatureMessageX962SHA256
        guard SecKeyIsAlgorithmSupported(privateKey, .sign, algorithm) else {
            throw NEXUSSignError.keyOperationFailed(status: errSecUnimplemented)
        }
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(privateKey, algorithm, payload as CFData, &error) as Data? else {
            throw Self.mapKeyError(error)
        }
        return signature
    }

    /// Signs a request with the authentication key. No user prompt.
    func signRequest(_ input: Data) throws -> Data {
        guard let key = try existingKey(.authentication) else { throw NEXUSSignError.notRegistered }
        return try sign(payload: input, using: key)
    }

    /// ECDH (X9.63 standard, the 32-byte x coordinate) between the offline key
    /// and Auth Core's key returned at enrolment. Shows the biometric prompt of
    /// `context`.
    func offlineSharedSecret(serverPublicKeyPEM: String, context: LAContext) throws -> Data {
        guard let privateKey = try existingKey(.offline, context: context) else {
            throw NEXUSSignError.offlineConfirmationUnavailable
        }
        let serverKey = try Self.publicKey(fromPEM: serverPublicKeyPEM)
        var error: Unmanaged<CFError>?
        guard let secret = SecKeyCopyKeyExchangeResult(privateKey, .ecdhKeyExchangeStandard, serverKey, [String: Any]() as CFDictionary, &error) as Data? else {
            throw Self.mapKeyError(error)
        }
        return secret
    }

    /// Maps a Security framework failure; user cancellation and failed
    /// biometrics become `authenticationDenied`.
    private static func mapKeyError(_ error: Unmanaged<CFError>?) -> NEXUSSignError {
        // takeRetainedValue() transfers ownership: call it exactly once.
        let underlying = error?.takeRetainedValue() as Error?
        if let laError = underlying as? LAError, laError.code == .userCancel || laError.code == .authenticationFailed {
            return .authenticationDenied
        }
        let status = (underlying as NSError?)?.code ?? Int(errSecParam)
        if status == Int(errSecUserCanceled) || status == Int(errSecAuthFailed) {
            return .authenticationDenied
        }
        return .keyOperationFailed(status: OSStatus(status))
    }

    /// DER header of a P-256 SubjectPublicKeyInfo with an uncompressed point.
    private static let p256SPKIHeader = Data([
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ])

    /// A P-256 public key from SPKI PEM (26-byte SPKI header + uncompressed point).
    private static func publicKey(fromPEM pem: String) throws -> SecKey {
        let base64 = pem.components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && !$0.hasPrefix("-----") }
            .joined()
        guard let der = Data(base64Encoded: base64), der.count == 91, der.prefix(26) == p256SPKIHeader else {
            throw NEXUSSignError.keyOperationFailed(status: errSecParam)
        }
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256,
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(der.suffix(65) as CFData, attributes as CFDictionary, &error) else {
            throw mapKeyError(error)
        }
        return key
    }
}

enum SecureEnclaveSupport {
    static var isAvailable: Bool {
        #if targetEnvironment(simulator)
        return false
        #else
        return true
        #endif
    }
}
