import Foundation

/// Non-secret SDK state persisted per bank (keys namespaced by `bankID`):
/// the credential registered by the last successful `bootstrap()` or
/// recovery, Auth Core's offline key-agreement public key, and whether a key
/// set confirmed by Auth Core still has to be promoted to the active tags.
struct SDKState {
    private let defaults: UserDefaults
    private let prefix: String

    init(bankID: String, defaults: UserDefaults = .standard) {
        self.defaults = defaults
        self.prefix = "com.nexis.nexussign.\(bankID)."
    }

    /// Credential ID confirmed by Auth Core; `nil` until enrolment succeeds.
    var registeredCredentialID: String? {
        get { defaults.string(forKey: prefix + "credentialId") }
        nonmutating set { defaults.set(newValue, forKey: prefix + "credentialId") }
    }

    /// Auth Core's half of the offline key agreement, returned at enrolment.
    var offlineServerPublicKeyPEM: String? {
        get { defaults.string(forKey: prefix + "offlineServerPublicKey") }
        nonmutating set { defaults.set(newValue, forKey: prefix + "offlineServerPublicKey") }
    }

    /// Registration of a confirmed key set whose promotion has not finished;
    /// applied together with the re-tag (see `KeyManager.finishPendingCommit`).
    var pendingCredentialID: String? {
        get { defaults.string(forKey: prefix + "pendingCredentialId") }
        nonmutating set { defaults.set(newValue, forKey: prefix + "pendingCredentialId") }
    }

    /// Whether Auth Core accepts device-signed requests for the registered
    /// (or pending) credential; otherwise the SDK uses session tokens.
    var deviceSignatures: Bool {
        get { defaults.bool(forKey: prefix + "deviceSignatures") }
        nonmutating set { defaults.set(newValue, forKey: prefix + "deviceSignatures") }
    }

    var pendingDeviceSignatures: Bool {
        get { defaults.bool(forKey: prefix + "pendingDeviceSignatures") }
        nonmutating set { defaults.set(newValue, forKey: prefix + "pendingDeviceSignatures") }
    }

    var pendingOfflineServerPublicKeyPEM: String? {
        get { defaults.string(forKey: prefix + "pendingOfflineServerPublicKey") }
        nonmutating set { defaults.set(newValue, forKey: prefix + "pendingOfflineServerPublicKey") }
    }

    /// Set when Auth Core has confirmed an enrolment or recovery and the replacement key is
    /// the credential, but the local re-tag has not completed yet.
    /// Stored under its 1.1 key, so a recovery interrupted before an upgrade still completes.
    var replacementCommitPending: Bool {
        get { defaults.bool(forKey: prefix + "recoveryCommitPending") }
        nonmutating set { defaults.set(newValue, forKey: prefix + "recoveryCommitPending") }
    }

    /// `LAContext.evaluatedPolicyDomainState` when the active keys were
    /// enrolled. A different value later means the biometric enrolment changed
    /// and the biometry-bound keys are gone.
    var biometryDomainState: Data? {
        get { defaults.data(forKey: prefix + "biometryDomainState") }
        nonmutating set { defaults.set(newValue, forKey: prefix + "biometryDomainState") }
    }
}
