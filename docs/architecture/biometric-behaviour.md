# Biometrics and key storage: one behaviour on iOS and Android

Every signature of the customer (payment, mandate, recovery setup, offline code) needs a key that the platform releases only after a strong biometric check: Secure Enclave keys with `.biometryCurrentSet` on iOS, Android Keystore keys with `setUserAuthenticationRequired(true)` and `setInvalidatedByBiometricEnrollment(true)` on Android (StrongBox when present, else TEE). This page states what the SDKs do in each situation, so that a bank app handles both platforms with one flow. Finding D-07 (iOS kept dead keys after a biometric change) is fixed in code on this branch.

## The situations

| Situation | What the platform does | SDK result (both) | What the bank app does | Code |
|---|---|---|---|---|
| Biometrics enrolled, check passes | Releases the key for one operation | Signature | — | iOS `KeyManager.sign`, Android `authenticate(…CryptoObject…)` |
| Customer cancels or fails the check | Key not released | `authenticationDenied` / `AuthenticationDenied` | Ask again or stop | iOS `mapKeyError`, Android `biometricError` |
| Too many failed attempts | Biometrics locked until the passcode is entered | `biometryLockedOut` / `BiometryLockedOut` | Tell the customer to unlock with the passcode | iOS `biometryError`, Android `ERROR_LOCKOUT`, `ERROR_LOCKOUT_PERMANENT` |
| No biometrics enrolled (never, or all removed) | No strong biometric to check | `noAuthenticationMethodEnrolled` / `NoAuthenticationMethodEnrolled` | Ask the customer to set up Face ID, Touch ID or a fingerprint | iOS `canEvaluatePolicy`, Android `requireBiometrics` |
| Biometric hardware absent or disabled by policy | — | `biometryUnavailable` / `BiometryUnavailable` | The device cannot be used for NEXUS-SIGN | same |
| **A finger or face added or removed after enrolment** | The keys are permanently invalid (`.biometryCurrentSet`, `KeyPermanentlyInvalidatedException`) | `credentialInvalidated` / `CredentialInvalidated`, and the SDK **deletes the dead keys and the registration**: `isRegistered()` becomes false | Re-enrol the device: device replacement by the bank, or recovery with the phrase. Auth Core keeps the old credential until the bank revokes it or the replacement revokes it | iOS `withBiometryCheck` → `KeyManager.forgetInvalidatedCredential()` (since this branch), Android `KeyManager` `deleteSet(slot)` + `forgetRegistration()` |
| Re-enrolment after that | New keys under the current biometrics | Normal enrolment through `bootstrap()` with a replacement token, or `recover(…)` | As for a new device; the hold of the [device replacement](device-replacement.md) applies unless the customer approves on another active device | |
| Credential revoked at Auth Core (bank, customer, console) | Keys still exist on the device | Every device request answers 401 (unknown credential); the SDK reports `serverError(401)` / `ServerError(401)`. A suspended or revoked NEXUS ID answers 403 | Re-enrol (replacement or recovery); for 403 the bank reactivates or replaces the identity | Auth Core `middleware/mobileAuth.ts` |
| Hardware key storage unavailable | iOS: no Secure Enclave (simulator, very old devices). Android: Keystore fails | `secureEnclaveUnavailable` / `KeystoreUnavailable` at enrolment | The device cannot be used | iOS `generateKey`, Android `KeyManager` |
| StrongBox absent (Android only) | Keys are created in the TEE | Enrolment continues; `securityLevel` reports `TEE`; the attestation tells Auth Core | The bank's attestation policy decides whether TEE keys are accepted | Android `KeyManager` generation fallback, Auth Core attestation policy |
| Device locked (Android only) | Keys with unlocked-device requirement unusable | `DeviceLocked` | Ask the customer to unlock | Android |
| Recovery | New keys are created and replace the old ones only when Auth Core accepts the recovery | Normal result; on failure the old keys stay | — | iOS `withReplacementKeys`, Android key slots |

## What changed on iOS (D-07)

Before: on a biometric change iOS reported `credentialInvalidated` but kept the three dead Secure Enclave keys and the registration, so `isRegistered()` stayed true and every `approve` showed a Face ID prompt that could not succeed. Now `withBiometryCheck` deletes the active keys (and a pending replacement set), clears the registration fields and the device identity used to sign requests, then throws `credentialInvalidated`, as Android does.

Detection on iOS still depends on `LAContext.evaluatedPolicyDomainState`, recorded at enrolment. For a credential enrolled before the SDK recorded it, a biometric change appears as `authenticationDenied`; the customer then needs the bank to replace the device.

## Not verified

Nothing on this page was run on a device in the review environment: there is no Xcode, no iOS device and no Android device. The Kotlin parts outside the Android framework (the call engine, payload parsing, protocols) run on the JVM; the Keystore, BiometricPrompt and the Secure Enclave do not.

### Device test procedure (both platforms)

Run on one iPhone with Face ID, one with Touch ID, one Android phone with StrongBox and one without, with the demo app or the bank app:

1. Enrol. Confirm a payment. Expected: signature accepted.
2. Cancel the prompt. Expected: `authenticationDenied`; no request reaches Auth Core.
3. Fail the check until lockout. Expected: `biometryLockedOut`.
4. Add a second fingerprint or an alternative face appearance. Confirm a payment. Expected: `credentialInvalidated` on the first attempt, `isRegistered()` false afterwards, no second biometric prompt, and the keys gone (iOS: no item with tag `com.nexis.nexussign.<bankID>.signingKey`; Android: no alias in the Keystore).
5. Re-enrol through device replacement. Expected: the hold applies; after it, the new device confirms; the old credential is revoked.
6. Remove all biometrics. Expected: `noAuthenticationMethodEnrolled` before any key access.
7. Revoke the credential in the console. Expected: next request `serverError(401)`. Suspend the NEXUS ID instead: `serverError(403)`.
8. Android without StrongBox: enrol. Expected: `securityLevel` TEE in the console's device screen; the bank policy decides.

Record the SDK version, OS version, device model and the result of each step in the [device acceptance checklist](../engineering/DEVICE_ACCEPTANCE_CHECKLIST.md).
