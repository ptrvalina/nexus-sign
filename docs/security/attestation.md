# Device attestation

Auth Core verifies device attestation at enrolment (`POST /v1/mobile/bootstrap`) and recovery completion: App Attest on iOS, Play Integrity together with Android Keystore key attestation on Android. With `REQUIRE_VALID_ATTESTATION=true` (production) a failed attestation refuses the request with 403, and a credential enrolled without verified attestation cannot approve transactions (409 `CREDENTIAL_NOT_ATTESTED`) until the device is enrolled again. The stored platform and security level are taken from the verified attestation, not from the app's claim. Attestation is not repeated per operation. Recovery itself is specified in [recovery protocol 2](../protocol/recovery-protocol-v2.md). Decision record: [ADR 0011](../adr/0011-android-key-attestation-policy.md).

Implementation: `auth-core/src/services/attestationBinding.ts`, `attestationVerificationService.ts` (policy, both keys, Play Integrity), `appAttestService.ts`, `playIntegrityService.ts`, `androidKeyAttestation.ts` (chain and KeyDescription checks), `src/crypto/androidAttestationRoots.ts` (pinned roots). On the device: `KeyManager.swift`, `KeyManager.kt`, `NEXUSSignSDK.kt`.

## Session-bound attestation

The challenge is derived by Auth Core and the SDK from the single-use `BOOTSTRAP` token (`attestationChallenge`) or from the recovery session nonce. One attestation covers all device keys:

```text
binding = challenge || 0x00 || signing PEM || 0x00 || authentication PEM || 0x00 || offline PEM
```

App Attest attests `SHA-256(binding)`; the Play Integrity nonce is `base64url(SHA-256(binding))`. Auth Core accepts only strict PEM text, so no key can be moved between fields, and an attestation captured in one enrolment or recovery session cannot be transplanted into another session or onto another key. When attestation is unavailable on a device, the SDK still sends the enrolment with the reason; with `REQUIRE_VALID_ATTESTATION=true` Auth Core refuses it. The derivation is pinned by a known-answer test in `auth-core/test/crypto.test.mjs`.

Evidence from one platform cannot enrol a credential claimed for the other: an Android verdict with `platform: IOS`, or the reverse, is treated as not verified.

## iOS: App Attest

- The signing, authentication and offline keys are Secure Enclave P-256 keys and are not exportable. The signing key requires biometric authorization for every use (`.biometryCurrentSet`), so adding or removing a fingerprint or face makes it unusable (`credentialInvalidated`).
- App Attest is verified against the pinned Apple root CA (`APPLE_APP_ATTEST_ROOT_CA_PEM`): nonce, key ID, `rpIdHash`, counter and environment (production and development are separate).
- A verified App Attest attestation is stored with security level `SECURE_ENCLAVE`: it proves a genuine instance of the app, which creates its keys only in the Secure Enclave.

## Android: Play Integrity

The integrity token is decoded through Google (`GOOGLE_SERVICE_ACCOUNT_JSON`). Its nonce must match the binding above; the app must be `PLAY_RECOGNIZED` with package `ANDROID_PACKAGE_NAME` and a signing certificate digest in `ANDROID_APP_CERT_SHA256` (when set), the token must be fresh (`ATTESTATION_MAX_AGE_SECONDS`), and the device verdicts must include `ANDROID_REQUIRED_DEVICE_VERDICT`. Key attestation is checked only after Play Integrity passes. Play Integrity says that a recognized copy of the bank's app runs on a device that meets the required verdict; key attestation says, for each hardware key, where it was generated, that it belongs to this enrolment and to the bank's app, how it may be used, and the state of the bootloader.

## Android key attestation

### What the SDK sends

The Android SDK generates the signing and authentication keys with `setAttestationChallenge()` (StrongBox first, TEE fallback) and sends their certificate chains, leaf first, as base64 DER:

```json
"deviceAttestation": {
  "integrityToken": "…",
  "keyAttestation": { "signingKeyChain": ["<leaf>", "…", "<root>"], "authenticationKeyChain": ["…"] }
}
```

```text
keyAttestationChallenge = SHA-256("NEXUS-SIGN/KEY-ATTESTATION/v1" || 0x00 || enrolment challenge)
```

The derivation is pinned by `key_attestation` in `auth-core/test-vectors/device-protocols-v1.json`. The offline key (an HMAC key) and the push key are imported into the Keystore; imported keys carry no generation attestation, so neither is covered.

### Order of checks

1. Play Integrity, as above.
2. Chains present: a signing key chain and an authentication key chain, each of 2 to 10 certificates. Without a signing key chain, enrolment fails unless the policy is `ALLOW_SOFTWARE`.
3. Each chain is verified as below, the signing key with the user authentication requirement, the authentication key without it.
4. The weaker of the two keys' levels is the credential's security level.

### Chain verification

| Check | Rule |
|---|---|
| Signatures | Each certificate is signed by the next one |
| Certification path | Every issuing certificate is a CA (`basicConstraints` cA), may sign certificates (`keyUsage` keyCertSign when present), respects its path length constraint, is not itself an attested Keystore key (no KeyDescription extension), and is named as the issuer (OpenSSL's issuer check: names, key identifiers, key usage). The attested key's certificate is not a CA. Without these checks, the key of a genuine attestation leaf, which the device owner can use, could sign a forged leaf with any KeyDescription |
| Root | The last certificate's public key is one of the pinned Google roots, and the certificate is self-signed |
| Validity | Remote Key Provisioning chains (a certificate subject contains `CN=Droid CA`): every certificate must be within its validity period. Factory-provisioned chains are accepted after expiry, as Google's guidance states |
| Revocation | No certificate serial (lowercase hex, without leading zeros) is in the [status list](#status-list); an entry of any status (`REVOKED`, `SUSPENDED`) refuses the chain |
| Leaf key | The leaf certificate's public key is the enrolled public key (SubjectPublicKeyInfo compared byte for byte) |

`androidAttestationRoots.ts` embeds two roots, taken from `github.com/android/keyattestation` and compared with Google's published list: the RSA-4096 root (serial `F1C172A699EAF51D`, 2022), whose public key is shared by the roots issued in 2016, 2019 and 2021, and the ECDSA P-384 "Key Attestation CA1" root (2025). Trust is anchored on the root public key, not on a certificate fetched at run time.

### KeyDescription checks

The leaf's KeyDescription extension (OID `1.3.6.1.4.1.11129.2.1.17`):

| Field | Rule |
|---|---|
| `attestationChallenge` | Equals `keyAttestationChallenge` for this enrolment |
| Security level | The lower of `attestationSecurityLevel` and `keyMintSecurityLevel`: `SOFTWARE`, `TEE` or `STRONGBOX`; it must meet the policy |
| `origin` (hardware-enforced) | `GENERATED`: created inside the secure hardware, not imported |
| `algorithm`, `ecCurve` (hardware-enforced) | EC, P-256 |
| `purpose` (hardware-enforced) | Includes `SIGN` |
| User authentication (signing key only) | `noAuthRequired` absent and `userAuthType` (hardware-enforced) includes the biometric authenticator |
| `rootOfTrust` (hardware-enforced) | With `ANDROID_REQUIRE_LOCKED_BOOTLOADER` (default `true`): `deviceLocked` is true and `verifiedBootState` is `VERIFIED` |
| `attestationApplicationId` | Software-enforced list, or hardware-enforced if absent; required. Its package names include `ANDROID_PACKAGE_NAME`; when `ANDROID_APP_CERT_SHA256` is set, one of its signature digests is configured |

The `origin`, `algorithm`, `ecCurve` and `purpose` checks are skipped under `ALLOW_SOFTWARE`. Other KeyDescription tags are parsed past and not evaluated.

### Policy

`ANDROID_KEY_SECURITY_POLICY`:

| Value | Accepts |
|---|---|
| `REQUIRE_STRONGBOX` | Keys whose attested level is `STRONGBOX` |
| `REQUIRE_HARDWARE_BACKED` (default) | `TEE` or `STRONGBOX` |
| `ALLOW_TEE` | `TEE` or `STRONGBOX`; the same acceptance as `REQUIRE_HARDWARE_BACKED` |
| `ALLOW_SOFTWARE` | Any level, including `SOFTWARE`; an enrolment without a signing key chain is accepted with level `SOFTWARE`. Development only: a production blocker |

A key that does not meet the policy fails the attestation; nothing falls back to a weaker level. Production blockers when Android attestation is configured: `ALLOW_SOFTWARE`, no `ANDROID_ATTESTATION_STATUS_FILE`, no `ANDROID_APP_CERT_SHA256`, `ANDROID_REQUIRE_LOCKED_BOOTLOADER=false` and `ANDROID_REQUIRED_DEVICE_VERDICT=MEETS_BASIC_INTEGRITY` ([configuration](../operations/configuration.md#production-blockers)).

| Verdict | Stored `security_level` | `attestation_status` |
|---|---|---|
| Android attestation verified | The weaker attested level of the signing and authentication keys (`TEE`, `STRONGBOX`; `SOFTWARE` only under `ALLOW_SOFTWARE`) | `VERIFIED` |
| iOS App Attest verified | `SECURE_ENCLAVE` | `VERIFIED` |
| Not verified (only without `REQUIRE_VALID_ATTESTATION`) | The client's `securityLevel` field | `UNKNOWN` |

The chains, the Play Integrity token digest, the decoded device verdicts and the derived level are sealed in the credential's `CREDENTIAL_ENROLLED` evidence record ([evidence format](../protocol/evidence-format.md#credential_enrolled)), so a third party can re-check the chains against Google's roots later.

### Status list

Google publishes the attestation status list at `https://android.googleapis.com/attestation/status`. Auth Core does not download it; operations write it to `ANDROID_ATTESTATION_STATUS_FILE` (Google's JSON format, `{ "entries": { "<serial hex>": { "status": "REVOKED", "reason": "…" } } }`) on a schedule, replace the file atomically and monitor the download ([runbook](../operations/runbooks/android-attestation-status-list.md)). Auth Core re-reads the file at most once a minute and does not check its age; a stale file accepts newly revoked attestation keys. If the file is missing or cannot be read or parsed, every Android key attestation fails (`the attestation status list is unavailable`). Without `ANDROID_ATTESTATION_STATUS_FILE` (outside production only) no revocation check is made.

### Tests

`auth-core/test/android-key-attestation.test.mjs` uses real device chains, copied unchanged with their expected values from `android/keyattestation` (`test/fixtures/android-key-attestation/`):

| Fixture | Level | Root |
|---|---|---|
| `frankel_sdk37_TEE_EC_2026` | TEE, attestation version 500 | ECDSA P-384 Key Attestation CA1 |
| `tegu_sdk36_SB_EC_2026_ROOT` | StrongBox, version 300 | ECDSA P-384 Key Attestation CA1 |
| `caiman_sdk36_TEE_EC_RKP` | TEE, version 400, Remote Key Provisioning | RSA root |

The chains are verified at the keys' `creationDateTime`, because their RKP intermediates are short-lived. The tests cover the reported levels; the StrongBox policy refusing a TEE key; refusal for another challenge, public key, package, signing certificate and a key without the biometric requirement; a foreign leaf, a chain cut before the root, an expired RKP chain and a revoked intermediate; the status list format; the challenge derivation against the shared vector; and, with the synthetic chains in `synthetic-path-chains.json` under a test root, refusal of a leaf issued by an attested Keystore key, by a CA without `keyCertSign` and beyond a path length constraint, next to a well-formed control chain. `status-example.json` is synthetic data in Google's format; one entry is the serial of the TEE sample's RKP attestation certificate, so the revocation path runs against a real chain.

`auth-core/test/device-attestation-policy.test.mjs` covers enrolment without chains, the weaker level of the two keys, a failing chain failing the enrolment, cross-platform evidence and the iOS level. `test/integration/attestation-policy.test.mjs` checks that an `UNKNOWN` credential cannot approve once `REQUIRE_VALID_ATTESTATION` is on.

Not covered by these tests: the acceptance of a biometric-bound signing key and the refusal of an unlocked device with a real chain (the sample chains have no user authentication and a locked bootloader), and the SDK side (key generation with the challenge, StrongBox selection, sending the chains, the biometric binding), which can only be verified on devices and has not been yet ([device acceptance checklist](../engineering/DEVICE_ACCEPTANCE_CHECKLIST.md)). Genuine App Attest and Play Integrity tokens are not exercised automatically.

### Not checked

- The key's per-use authentication timeout, the OS version and patch levels, the verified boot key, device identifiers (`attestationId*`) and key creation time.
- Periodic Play Integrity checks and per-operation attestation are not implemented.
