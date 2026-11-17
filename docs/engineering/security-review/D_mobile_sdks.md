# D — Native mobile SDKs audit (iOS / Android / calls modules)

Read-only static review of branch `engineering/production-readiness` at `4eef752` ("Refuse look-alike and layout tricks in displayed transaction text"). Nothing was compiled or run: this environment has no Swift toolchain, no Android SDK or Gradle dependencies, and no devices. Any conclusion about Keystore, Secure Enclave, BiometricPrompt, LocalAuthentication, App Attest, Play Integrity or WebRTC runtime behaviour is **UNVERIFIED** until it is tested on devices. Paths are relative to the repository root.

## 1. Scope actually read

- **iOS core, read in full:** `ios-sdk/Package.swift`, `KeyManager.swift`, `NEXUSSignSDK.swift`, `NetworkClient.swift`, `CertificatePinning.swift`, `NEXUSSignConfig.swift`, `SDKState.swift`, `AttestationProvider.swift`, `SignedTransaction.swift`, `DeviceProtocol.swift`, `OfflineSignatureQueue.swift`, `SecurePush.swift`, `RecoveryPhrase.swift`, `RecoveryProtocol.swift`. **Searched only:** `VerificationCall.swift`, `NEXUSSignModels.swift`.
- **Android core, read in full:** `build.gradle.kts`, `consumer-rules.pro`, `AndroidManifest.xml`, `KeyManager.kt`, `KeySlots.kt`, `NEXUSSignSDK.kt`, `NetworkClient.kt`, `NEXUSSignConfig.kt`, `AttestationProvider.kt`, `SignedTransaction.kt`, `DeviceProtocol.kt`, `OfflineSignatureQueue.kt`, `SecurePush.kt`, `RecoveryPhrase.kt`, and `NEXUSSignModels.kt` (the part that builds the signed transaction). **Searched only:** `VerificationCall.kt`.
- **Tests:** `SignedTransactionTests.swift`, the list of test methods in every iOS and Android test file, and `SignedTransactionTest.kt` (structure). The shared vectors in `signed-payload-v1.json` were decoded, and the iOS copy is byte-identical to the one in `auth-core/test-vectors/` (`cmp`).
- **Calls modules:** `ios-sdk-calls/Package.swift`, `WebRTCCallEngine.swift`, the permissions part of `VerificationCallView.swift`; `android-sdk-calls/build.gradle.kts`, `settings.gradle.kts`, `AndroidManifest.xml`, `CallPermissions.kt`, and `WebRtcCallEngine.kt` lines 1–140.
- **Demos:** `demo/android` (manifest, `network_security_config.xml`, `build.gradle.kts`, `DemoBank.kt`), `demo/ios/DemoBank.swift`, and the `.pbxproj` (Info.plist keys and entitlements).
- **Cross-checked:** `auth-core/src/services/canonicalAuthorization.ts` (display text rules), and `auth-core/src/routes/nexusV1.ts:31` together with `mobileV1.ts:260` (timestamp format).
- **Docs:** ADR 0005; `docs/security/attestation.md`; `offline-confirmation-v2-deferred-signature.md` (states and downgrade); the backup sections of both READMEs; `DECISION_LOG.md` (pinning).
- **Not read in full (limited time):** the other ADRs (0002, 0003, 0011, 0012, 0017, 0018), `NATIVE_BUILD_GUIDE.md`, `DEVICE_ACCEPTANCE_CHECKLIST.md` (only grepped), `THIRD_PARTY_MEDIA.md`, `deviceProtocol.ts`, the call controllers (`VerificationCall.*`, about 960 lines), `VerificationCallView.*`, `VerificationCallSession.kt`, `MainActivity.kt` and `DemoModel.swift`. Findings do not depend on them unless a finding says so.

## 2. Findings table

No Critical or High finding was confirmed.

| ID | Sev | Platform | Title | Location | Status |
|---|---|---|---|---|---|
| D-01 | Medium | iOS | The static ECDH offline secret is returned to app memory on every use, so one capture forges offline codes forever without biometrics | `ios-sdk/Sources/NEXUSSign/KeyManager.swift:312-322`, `NEXUSSignSDK.swift:309-312` | Confirmed (design, by code) |
| D-02 | Medium | both | The prompt text has no field labels and its separators are not reserved, so a payee name can carry a second "account number" | `SignedTransaction.swift:43-49,369-379`; `SignedTransaction.kt:49-54,280-285` | Confirmed |
| D-03 | Low | both | New display rules: full-width and mathematical Latin letters, other confusable scripts, whole-script confusables and non-decimal digits all pass; IBAN check digits 00/01/99 are accepted | `SignedTransaction.swift:292-330,333-350`; `SignedTransaction.kt:241-274` | Confirmed |
| D-04 | Low | both | `operation_type` appears in the prompt but only the control-character rule applies to it | `SignedTransaction.swift:47,180-184`; `SignedTransaction.kt:53,140-142`; `auth-core/src/routes/nexusV1.ts:31` | Confirmed |
| D-05 | Low | iOS | The response cross-check uses Swift `String ==` (canonical equivalence), not code-unit equality | `SignedTransaction.swift:238-247` | Confirmed |
| D-06 | Low | iOS | Registration state and the v2 offline-signature queue live in `UserDefaults`: writes across several keys are not atomic and not guaranteed durable, and the files are included in backups | `KeyManager.swift:133-143`; `SDKState.swift:7-67`; `OfflineSignatureQueue.swift:61-66,88-100` | Suspected (needs a power-loss test) |
| D-07 | Low | iOS | After a biometric change, iOS reports `credentialInvalidated` but keeps the dead keys and the registration (Android deletes both) | `NEXUSSignSDK.swift:433-443` vs `NEXUSSignSDK.kt:166-171`, `KeyManager.kt:311-313` | Confirmed |
| D-08 | Low | both | Certificate pinning is off by default and in both demos; the iOS push receipt bypasses configured pins | `NEXUSSignConfig.swift:56`; `NEXUSSignConfig.kt:341`; `NEXUSSignSDK.swift:423-426`; `SecurePush.swift:250` | Confirmed |
| D-09 | Low | both | Secure push has no replay or freshness check | `SecurePush.swift:213-237`; `SecurePush.kt:413-428,490-494` | Confirmed |
| D-10 | Low | both | Recovery phrase normalization differs: Kotlin `\s` is ASCII-only, Swift `isWhitespace` is Unicode | `RecoveryPhrase.kt:161-164`; `RecoveryPhrase.swift:31-35` | Confirmed |
| D-11 | Low | iOS | Error model: an internal error type escapes a public API, and `serverError(statusCode: 0/200)` is used for client-side failures | `RecoveryPhrase.swift:10-13`, `NEXUSSignSDK.swift:169,183,211,229,454`; `NetworkClient.swift:158,173,179` | Confirmed |
| D-12 | Low | iOS | Blocking Secure Enclave biometric calls and PBKDF2 with up to 5M iterations run synchronously inside `async` methods of a non-isolated class | `NEXUSSignSDK.swift:147-150,186,214,300-309` | Suspected (impact) |
| D-13 | Low | Android | Key bytes cleared after import are only the caller's copy (`SecretKeySpec` clones the array) | `KeyManager.kt:221-233`; `SecurePush.kt:457-471`; `NEXUSSignSDK.kt:441` | Confirmed |
| D-14 | Low | both (calls) | WebRTC: DTLS-SRTP is not asserted, ICE transport policy is left at `all`, and the libwebrtc binaries are unofficial | `WebRTCCallEngine.swift:42-47`; `WebRtcCallEngine.kt:92-104` | Confirmed (config); runtime UNVERIFIED |
| D-15 | Low | iOS | The App Attest entitlement and capability are not documented for integrators, and the demo has none | `ios-sdk/README.md` (no mention); `demo/ios/...pbxproj` (no `CODE_SIGN_ENTITLEMENTS`) | Suspected |
| D-16 | Info | Android | Software-backed keys are not refused on the device; the SDK relies on the Auth Core attestation policy | `KeyManager.kt:327-336,386-405` | Confirmed |
| D-17 | Info | both | Engineering: orphaned or duplicated doc comments, stale comments, a dead elvis operator | see section 3 | Confirmed |

Totals: 0 Critical, 0 High, 2 Medium, 13 Low, 2 Info.

## 3. Findings

### D-01 (Medium, iOS): the offline secret is reusable once it leaves the Secure Enclave

**What the code does.** `KeyManager.swift:318`:
```swift
SecKeyCopyKeyExchangeResult(privateKey, .ecdhKeyExchangeStandard, serverKey, [String: Any]() as CFDictionary, &error) as Data?
```
This returns the raw ECDH secret to the app process. `NEXUSSignSDK.swift:309-312` then derives the HMAC key and computes the tag in app memory. The device key is static (the SE `offline` key), and so is the server key (`effectiveOfflineServerPublicKeyPEM`, fixed at enrolment). The shared secret, and the HKDF output (`DeviceProtocol.swift:243-251`), are therefore the same for every transaction. The `resetBytes` call at line 310 clears one copy, but the `SymmetricKey` and any captured copy remain.

**Why this is wrong.** The documented property ("offline: biometric, every use", `KeyManager.swift:12`) holds for the ECDH operation, not for the secret that authorizes codes. Android, by contrast, imports the derived key once into the Keystore as a non-exportable HMAC key behind a per-use `CryptoObject` (`KeyManager.kt:223-230`, `NEXUSSignSDK.kt:355-365`).

**Attack.** Code running in the bank app's process captures the 32-byte secret once, for example on a jailbroken device, through an instrumented or compromised third-party dependency, or with a debugger on a development build. From then on it can compute valid 8-digit codes for any QR (any amount, any payee) for that credential, without the customer and without biometrics, until re-enrolment. With v2 (`NXS2.`) such a code only reaches `OFFLINE_PROVISIONAL`, then `OFFLINE_UNSIGNED`, because there is no device signature. With v1, or if a bank treats "not FAILED" as success (`offline-confirmation-v2…md:134`), the code is final.

**Minimal fix.** Remove the static-static derivation. Put a per-authorization server ephemeral P-256 public key into the canonical offline payload (or the QR), and run the SE ECDH against it for each code. A captured secret then serves one transaction only. Until the protocol changes: keep `OFFLINE_CONFIRMATION_MODE=deferred_signature` mandatory in production, and state in the iOS README that v1 offline codes on iOS do not have per-use hardware binding.

**Verify.** Unit test: two QR codes give two different HKDF keys. On a device: Frida hooking `SecKeyCopyKeyExchangeResult` shows the secret before and after the fix.

### D-02 (Medium, both): ambiguous prompt layout

**What the code does.**
```swift
var text = "\(formattedAmount) \(currency)"; if !who.isEmpty { text += " → \(who)" }
text += "\n\(operationType) • \(transactionReference)"
```
`who` is `[account, name, bic] + sorted(rest)` joined with `" · "`, with no field labels (`SignedTransaction.swift:43-49,371-379`; Kotlin `:49-54,280-285`). The new display rules allow `name`, `note` or any other key to hold `PL61109010140000071219812874` or the characters `→ · •`: digits, ASCII letters and those symbols are all accepted (`displayTextViolation`).

**Scenario.** The bank creates an authorization from payee data typed from a fraudulent invoice: `iban = <mule IBAN>`, `name = "PL61 1090 1014 0000 0712 1981 2874"` (spaces are allowed in `name`), or `note = "→ PL61…"`. The prompt reads `1250.00 PLN → <mule IBAN> · PL61 1090 … 2874`. A customer who checks the last digits matches the second, attacker-chosen value. Signed bytes and display are still identical, so WYSIWYS holds technically, but the display does not tell the customer which value is the account.

**Fix.** Label fields in `confirmationText` (for example `"To: <iban>\nName: <name>"`), with localizable labels passed in by the host app. Alternatively, reserve `→ · •` in all display values and reject a `name` that matches the IBAN shape. Add the cases to the shared vectors so Auth Core, Swift and Kotlin agree.

**Verify.** New vectors in `signed-payload-v1.json` (invalid: name that looks like an IBAN; separator inside a value). On a device: screenshots of the Face ID and BiometricPrompt dialogs with 140-character names (BLOCKED EXTERNAL).

### D-03 (Low, both): gaps in the new display rules, plus a compile-risk review

**What the code does.** Mixed-script detection covers only three fixed sets: Latin `0x41-0x24F, 0x1E00-0x1EFF`, Cyrillic `0x400-0x52F` and Greek `0x370-0x3FF, 0x1F00-0x1FFF` (`SignedTransaction.swift:292-296`, `.kt:241-245`, `canonicalAuthorization.ts` identical). The digit rule checks only category `Nd`.

**Confirmed gaps** (the Unicode categories were checked with Python `unicodedata`):
- `"ＰayPal"`: U+FF30 FULLWIDTH LATIN CAPITAL LETTER P is in no set, so only one script is counted and the value passes. NFC does not fold full-width forms; NFKC would.
- `"𝐏ayPal"` (U+1D40F MATHEMATICAL BOLD CAPITAL P) passes the same way.
- Cherokee `Ꭺ` (U+13AA) and Armenian `Օ` (U+0555) look like Latin letters and pass.
- Whole-script confusables pass by design: an all-Cyrillic `РАУРАL` is accepted, and the valid vector "payee name in Cyrillic script" confirms that all-Cyrillic values are allowed.
- `²` (category `No`) passes the "ASCII digits only" rule.
- `isValidIBAN` accepts check digits `00`, `01` and `99`, which are congruent to `97`, `98` and `02`. ISO 13616 allows only 02–98.

**Fix.** Reject any letter outside the three sets (or allow-list scripts), reject `No`/`Nl` numbers, and add `value == NFKC(value)` to the rules on all four implementations. Require check digits 02–98. Add vectors for each case.

**Review of the new code (requested; nothing compiled):**
- *Swift `displayTextViolation`, `isValidIBAN`, `isValidBIC` (`:305-363`).* Every API used exists: `Unicode.Scalar.Properties.generalCategory` (iOS 10+/macOS 10.12+), the `.spaceSeparator`, `.decimalNumber`, `.control`, `.format`, `.lineSeparator` and `.paragraphSeparator` cases, `precomposedStringWithCanonicalMapping` (Foundation), and `String.UnicodeScalarView.last` (bidirectional). `guard` inside `switch` cases, a ternary inside a `guard` (`:360`), and `$0` inside an inner closure whose enclosing closures name their parameters (`:325-327`) are all legal Swift 5.9. Integer literal ranges infer `UInt8` and `UInt32` correctly. I see no compile error. The nested `filter`/`contains` closure at `:325-327` could hit slow type-checking, but is unlikely to fail. Logic: the mod-97 arithmetic is correct (a letter maps to 10–35, so `*100`). NFC is compared scalar by scalar, which is correct because Swift `==` would hide NFD.
- *Kotlin (`:255-274`).* `String.codePoints()` returns `IntStream`, and `anyMatch` takes an `IntPredicate` lambda via SAM conversion; `Character.SPACE_SEPARATOR.toInt()` is fine; `ch - 'A' + 10` gives `Int`; `java.text.Normalizer` exists on Android. `CharSequence.codePoints()` needs API 24, below minSdk 28. Kotlin turns the `\uXXXX` escapes inside the regex strings into literal characters, which the regex class accepts. No compile issue found.
- *Parity between Swift, Kotlin and TS.* Equivalent, with two differences. Kotlin `isDisplaySafe` also rejects `SURROGATE`, which a Swift `String` cannot contain, so this is harmless. Kotlin has no `isValidBic` function and uses the `BIC` regex instead; the result is the same as Swift `isValidBIC` and the TS `BIC`. The TS `PADDED` rule (`^\p{Zs}|\p{Zs}$`) equals the Swift and Kotlin leading/trailing-space checks once non-ASCII spaces are rejected. Category tests and NFC still depend on each runtime's Unicode version: Node ships Unicode 17, Android ICU and iOS older versions. Auth Core is the strictest, so drift makes the device more permissive, never stricter, for authorizations Auth Core created.
- *Ordering note.* Both SDKs run `isDisplaySafe` over all top-level strings before `displayTextViolation`, so the first rule message for a control character comes from the generic check. The `reason` code (`invalid_value`) is the same, and the vectors check only `reason`.

**Verify.** Add the vectors above. CI must actually run `swift test` (macOS) and `./gradlew test`; neither was run here.

### D-04 (Low, both): `operation_type` is outside the display rules

Line 2 of the prompt starts with `operationType`, but the SDKs apply only `isDisplaySafe` to it (`SignedTransaction.swift:180-184`), and Auth Core accepts `z.string().min(1).max(32)` (`nexusV1.ts:31`). A value such as `"transfer   "` or `"trаnsfer"` (Cyrillic а) is signed and shown. **Fix:** an enum or a pattern (`^[a-z][a-z_]{0,31}$`) in Auth Core and both parsers, plus a vector.

### D-05 (Low, iOS): canonical-equivalence comparison in `verify`

`try check("transactionReference", signed.transactionReference == envelope.transactionReference)`, and the same for `operationType`, `policyReference`, `beneficiary` and so on (`SignedTransaction.swift:241-247`). Swift `String ==` treats NFC and NFD as equal, so a response field in NFD passes on iOS and fails on Android (`.kt:189-195` uses Java `equals`). For beneficiary values and `transaction_reference` the NFC rule limits the effect. For `operation_type` and `policy_reference` it does not, and a host app that renders the JSON response fields would show bytes that differ from the signed ones. They look identical, so the impact is low. **Fix:** compare `Array(a.utf8) == Array(b.utf8)`, and for the dictionary compare sorted `(key, utf8)` pairs. **Verify:** a unit test with an NFD response field must throw `response_mismatch`.

### D-06 (Low, Suspected, iOS): non-atomic, non-durable state in UserDefaults

`commitReplacementKeys` makes five separate `defaults.set` calls (`KeyManager.swift:134-138`) and then deletes and re-tags keychain items (`:186-198`). Keychain changes are durable at once. UserDefaults is flushed asynchronously by `cfprefsd`. After a power loss or kernel panic in that window, the active tag can hold the new keys while `registeredCredentialID` still holds the old credential ID and `replacementCommitPending` is false. Requests are then signed with keys that do not match the credential, and the customer must re-enrol. ADR 0005 states the opposite guarantee ("never signs with keys whose credential ID it has not recorded"); Android meets it with a single `commit()` (`KeySlots.kt:42-50`).

The same applies to `OfflineSignatureQueue.add` (`OfflineSignatureQueue.swift:61-66,98-100`): the comment "Stored before the code exists" (`NEXUSSignSDK.swift:304`) is only as durable as cfprefsd. `remove` swallows errors with `try?` (`:90`). UserDefaults is also included in iCloud and iTunes backups; the README (`ios-sdk/README.md:142`) accepts this for registration state.

**Fix.** Store `SDKState` and the queue as one Codable blob in a keychain generic-password item (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`), written with a single `SecItemUpdate`/`SecItemAdd`, or as a file written with `Data.write(options: .atomic)` and `isExcludedFromBackup`.

**Verify.** On a device: kill the process and cut power right after `finishPendingCommit` (BLOCKED EXTERNAL). Unit: inject a `UserDefaults` suite and check that both fields are always read together.

### D-07 (Low, iOS): biometric change handling differs from Android

On Android, `KeyPermanentlyInvalidatedException` leads to `deleteSet(slot)` and `forgetRegistration()` (`KeyManager.kt:311-313`, `NEXUSSignSDK.kt:166-171`). On iOS, `withBiometryCheck` only rethrows `.credentialInvalidated` (`NEXUSSignSDK.swift:433-443`). The dead `.biometryCurrentSet` keys and `registeredCredentialID` stay, so `isRegistered()` remains `true` and every `approve` shows a Face ID prompt that cannot succeed. Detection also depends on `evaluatedPolicyDomainState`, which is `nil` for credentials enrolled before that field existed (`KeyManager.swift:157`), in which case the error is `authenticationDenied`.

**Fix:** on `.credentialInvalidated`, delete the three active keys and clear the registration fields, as Android does. **Verify:** on a device, enrol, add a fingerprint or face, then call `approve` (BLOCKED EXTERNAL: an iPhone with Face ID and one with Touch ID).

### D-08 (Low, both): pinning optional; iOS receipt bypasses pins

Pins default to empty (`NEXUSSignConfig.swift:56`, `.kt:341`), and neither demo sets them. This is acceptable by design: request signing and attestation key binding limit a man-in-the-middle to reading traffic. However, `confirmPushReceipt` calls `sendReceipt(… baseURL:, timeout:)` with the default `session: URLSession = .shared` (`SecurePush.swift:250`, `NEXUSSignSDK.swift:424-425`), so even a bank that configured pins sends receipts without them. Android sends receipts through the pinned `NetworkClient` (`NEXUSSignSDK.kt:487`). The iOS pin check accepts a match anywhere in the chain, root included (`CertificatePinning.swift:89`); document that pinning a public root CA adds nothing.

**Fix:** pass `CertificatePinning.session(pins: config.certificatePins)` into `sendReceipt`. For a Notification Service Extension, add a `certificatePins` parameter to `NEXUSSignPushReader`.

### D-09 (Low, both): push replay

`open` checks the AEAD (binding message ID and credential ID), the version and the content, but stores no seen message IDs and does not check `sentAt` (`SecurePush.swift:213-237`, `SecurePush.kt:413-428`). Anyone able to inject an FCM or APNs payload, such as a compromised push provider account or another app that shares the push token, can replay an old genuine envelope, for example an old `SECURITY` alert or an `AUTHORIZATION_REQUEST`. The authorization itself is re-fetched and verified, so no money moves; this is social-engineering surface only. **Fix:** an LRU of message IDs in the push keystore, and rejection of `sentAt` older than N hours.

### D-10 (Low, both): phrase normalization parity

Kotlin `split(Regex("\\s+"))` (`RecoveryPhrase.kt:162`) uses ASCII whitespace; Swift `split(whereSeparator: { $0.isWhitespace })` uses Unicode whitespace. A phrase pasted with U+00A0 or U+3000 between words is accepted on iOS and rejected on Android, which fails closed. Seed derivation uses the same functions (`RecoveryProtocol.swift:23`), so the two SDKs derive different passwords for such input. **Fix:** use the same explicit separator set on both, and add a vector to `recovery-v2.json`.

### D-11 (Low, iOS): error model leaks

- `RecoveryPhrase.generate()` throws the internal `RecoveryPhrase.GenerationError` out of the public `generateRecoveryPhrase()` (`NEXUSSignSDK.swift:183`), so callers cannot match it.
- `serverError(statusCode: 0, …)` is used for client-side validation failures (`:169, :211, :229, :454`), and `serverError(statusCode: 200, …)` for decode failures (`NetworkClient.swift:158,173,179`; `NEXUSSignSDK.swift:382,388`).
- The same pattern exists on Android (`ServerError(0, …)`, `NEXUSSignSDK.kt:204,249-256,576`).

**Fix:** add dedicated cases such as `invalidRecoverySession`, `invalidServerResponse` and `randomGenerationFailed`.

### D-12 (Low, Suspected, iOS): blocking work on the cooperative pool

`SecKeyCreateSignature` with a biometric ACL blocks until the user finishes the Face ID sheet (`NEXUSSignSDK.swift:147-150`, `:300-309`). PBKDF2 with up to 5,000,000 iterations runs synchronously (`:186`, `:214`). Both run inside `async` methods of a non-isolated `final class`. A blocked cooperative-pool thread for several seconds can starve other tasks. If the host calls from `@MainActor` code, the blocking work still runs on the generic executor (Swift 5.9 non-isolated async), so the UI is not frozen, but pool starvation is possible. **Fix:** move this work to a dedicated `DispatchQueue` and wrap it with `withCheckedThrowingContinuation`. This is a device test (BLOCKED EXTERNAL).

### D-13 (Low, Android): clearing an array that was already copied

`SecretKeySpec(derived, "HmacSHA256")` clones `derived`, so `derived.fill(0)` (`KeyManager.kt:230-232`) and `key.fill(0)` (`SecurePush.kt:471`) leave a copy on the heap until garbage collection. The same holds at `NEXUSSignSDK.kt:441`. The key bytes also pass through app memory once per enrolment or push registration; this is inherent to importing a key. **Fix:** none needed beyond correcting the comments ("wipes `key`", `NEXUSSignSDK.kt:445`), or generate inside the Keystore where the protocol allows it.

### D-14 (Low, both, calls): WebRTC configuration

Neither engine sets anything about DTLS (`WebRTCCallEngine.swift:42-47`, `WebRtcCallEngine.kt:92-104`). DTLS-SRTP is assumed from libwebrtc defaults: SDES was removed upstream, so M150/M153 should refuse non-DTLS media. This is UNVERIFIED for the stasel and webrtc-sdk builds, and the SDK does not check that the remote answer has `a=fingerprint`. The DTLS fingerprint is only as trustworthy as signalling (device-signed HTTPS requests to Auth Core). Pinning is optional (D-08), so a CA-level man-in-the-middle on signalling could substitute fingerprints. `iceTransportPolicy` stays `all`, so host and server-reflexive candidates expose the customer's local and public IP to the operator side. Both binaries are marked "DEVELOPMENT APPROVAL ONLY" (`ios-sdk-calls/Package.swift:7-10`, `android-sdk-calls/build.gradle.kts:48-52`). The SDK does not let a call result approve anything: `VerificationCall.swift:12-13,111` and `VerificationCall.kt:25-27,105` only map `decided:VERIFIED` to an end reason, and approval still requires `approve()` with biometrics (`NEXUSSignSDK.swift:126-156`). **Fix:** reject an answer SDP without `a=fingerprint:sha-256`; set `iceTransportPolicy = .relay` when Auth Core supplies TURN; close the binary provenance blocker.

### D-15 (Low, Suspected, iOS): App Attest entitlement not documented

`AttestationProvider` uses `DCAppAttestService` (`AttestationProvider.swift:13`). App Attest needs the `com.apple.developer.devicecheck.appattest-environment` entitlement and the App Attest capability on the App ID. Neither README nor the demo project (no `.entitlements` file, no `CODE_SIGN_ENTITLEMENTS`) mentions it. Without it, attestation may silently use the development environment or fail, and Auth Core (`REQUIRE_VALID_ATTESTATION=true`, separate environments, `attestation.md:3,22`) would then refuse production enrolment. **Fix:** document the entitlement in the integration steps. **Verify:** on a device with a paid Apple Developer team (BLOCKED EXTERNAL).

### D-16 (Info, Android): software keys are not refused locally

`generate` falls back from StrongBox to "TEE" on any exception (`KeyManager.kt:327-336`), and `securityLevel` can report `SOFTWARE_FALLBACK` (`:386-405`). The SDK never refuses a software key; the reported level is only a claim (`:132-134`). Per `docs/security/attestation.md:85-96`, Auth Core derives the level from the attestation chain, and `ALLOW_SOFTWARE` is a production blocker. This is correct if the server enforces it. **Verify** on an emulator, which yields a software attestation: enrolment must get 403 when Auth Core is configured for production.

### D-17 (Info): engineering hygiene

- `NEXUSSignSDK.swift:97-98`: the doc comment for `approve` is glued onto `openVerificationCall`, and `approve` (`:126`) has none.
- `NEXUSSignSDK.kt:56-57`: the KDoc for `isOfflineConfirmationAvailable` is orphaned above `signingKeyFingerprint`. `:120-124`: same pattern for `approve`.
- `NetworkClient.kt:63-64` and `DeviceProtocol.kt:358-359` stack two KDoc blocks.
- `SDKState.swift:35-36` still says "otherwise the SDK uses session tokens", but SESSION tokens were removed in 2.0 (`NEXUSSignConfig.swift:78`).
- `NEXUSSignSDK.kt:598` uses `(keys.offline ?: "")` on a non-null `String`, which is dead code and a compiler warning.
- Magic statuses `0` and `200` (D-11).
- `KeyManager.swift:99` and `:142` swallow errors with `try?` deliberately; this is commented and acceptable.
- No `TODO` or `FIXME` and no logging calls (`print`, `NSLog`, `Log.`, `println`) anywhere in the SDK, calls or demo sources (grep).

## 4. Security properties verified as correctly implemented (by code reading)

| Property | Evidence |
|---|---|
| iOS keys are generated only in the Secure Enclave (P-256, `kSecAttrTokenIDSecureEnclave`), with no software fallback; the simulator throws `secureEnclaveUnavailable` | `KeyManager.swift:217-258,367-375` |
| iOS signing and offline keys use `.privateKeyUsage + .biometryCurrentSet` (no passcode fallback, invalidated by enrolment change); the auth key uses `.privateKeyUsage`; all use `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` | `KeyManager.swift:119-121,228` |
| iOS: one prompt per signature. A fresh, unevaluated `LAContext` is bound via `kSecUseAuthenticationContext`, `localizedReason = signed.confirmationText`, and the bytes signed are `canonicalPayloadBase64` | `NEXUSSignSDK.swift:139-150`, `KeyManager.swift:73-77` |
| Android signing key: `setUserAuthenticationRequired(true)`; `setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)` on API 30+ (per use, strong biometrics only); per-use default on 28–29; `setInvalidatedByBiometricEnrollment(true)`; `DIGEST_SHA256`; `PURPOSE_SIGN`; attestation challenge set | `KeyManager.kt:355-366,344-348` |
| Android auth key: `setUnlockedDeviceRequired(true)`; enrolment requires `isDeviceSecure` | `KeyManager.kt:368-372`, `NEXUSSignSDK.kt:509-510` |
| Android StrongBox first, then TEE (any failure), minSdk 28 | `KeyManager.kt:327-348`, `build.gradle.kts:16` |
| Android: each signature or code goes through `BiometricPrompt` with a `CryptoObject` (`Signature`/`Mac`), `BIOMETRIC_STRONG` only, confirmation required, description = `confirmationText()` | `NEXUSSignSDK.kt:164-179,343-369,616-639` |
| Private keys are never exported: only `SecKeyCopyPublicKey`, `getCertificate().publicKey` and `getCertificateChain` are read | `KeyManager.swift:263-287`, `KeyManager.kt:351-381` |
| WYSIWYS parsing: the strict canonical parser re-encodes and compares bytes (rejects duplicate keys, alternative escapes, whitespace, unsorted keys, trailing data); every response field is cross-checked; the prompt, expiry and signed bytes come from the one verified payload | `SignedTransaction.swift:113-251`, `SignedTransaction.kt:110-199`, `NEXUSSignSDK.swift:126-150`, `.kt:154-179` |
| Encoding identical to Auth Core `JSON.stringify` over keys sorted by UTF-16 code unit (escaping `\" \\ \b \f \n \r \t \u00xx`, lowercase hex); beneficiary key pattern prevents the integer-key reordering | `SignedTransaction.swift:399-433`, `.kt:290-326`, `canonicalAuthorization.ts:130-160` |
| Amounts are formatted with integer string arithmetic and a fixed ISO 4217 table (no locale or NumberFormatter) | `SignedTransaction.swift:255-278`, `.kt:201-218` |
| Both suites run all valid and invalid shared vectors (47 invalid), the response-mismatch cases and the prompt-text vectors; the iOS copy is identical to `auth-core/test-vectors` and Android reads the originals | `SignedTransactionTests.swift:19-111`, `SignedTransactionTest.kt:22-100`, `build.gradle.kts:34-38` |
| IDs from push or deep links are validated as UUIDs before they become URL paths | `NEXUSSignSDK.swift:86,207,290,412`, `.kt:106,249,336,472` |
| Request signing: domain, method, path with query as sent on the wire, timestamp, 16-byte CSPRNG nonce, credential, SHA-256 of the body. The 401 clock correction is limited to ±24 h and to one retry. A rejected-auth retry cannot double-apply a POST | `NetworkClient.swift:187-269`, `NetworkClient.kt:207-267` |
| HTTPS enforced in config (loopback only otherwise; Android emulator host is opt-in) | `NEXUSSignConfig.swift:60-61`, `.kt:348-351` |
| Offline: code = RFC 4226 truncation of HMAC(domain‖0‖SHA-256(payload)); expiry checked; the v2 signature is stored before the code is computed; QR prefix downgrade (NXS2 to NXS1) fails safe server-side (`OFFLINE_UNSIGNED`) | `DeviceProtocol.swift:253-270`, `.kt:342-356`, `NEXUSSignSDK.swift:289-312`, `.kt:334-369`, doc `:31-34,72-80` |
| Secure push: ECDH P-256, HKDF-SHA256 (salt = domain, info = credential), AES-256-GCM with AAD = domain‖msgId‖credId, 12-byte IV; malformed envelopes are rejected with typed errors; the iOS push key is `AfterFirstUnlockThisDeviceOnly`, non-synchronizable; the Android key is a Keystore import, decrypt-only | `SecurePush.swift:19-48,143-153`, `SecurePush.kt:317-345,454-473` |
| Recovery: 128-bit entropy (`SecRandomCopyBytes` / `SecureRandom`); correct BIP-39 checksum; both wordlists are the canonical BIP-39 English list (SHA-256 `2f5eed53…dbda`, no CR); the phrase is never persisted or sent; the seed and wrap key are cleared on Android; iteration, salt and protocol bounds enforced (100k–5M, salt ≥16 B) | `RecoveryPhrase.swift:20-93`, `RecoveryPhrase.kt:149-200`, `NEXUSSignSDK.swift:448-457`, `.kt:568-579` |
| Two-phase key replacement serialized per process (actor / Mutex); Android pointer and registration in one `commit()` | `NEXUSSignSDK.swift:470-511,551-572`, `KeySlots.kt:39-51,79-87` |
| The calls modules never approve: a VERIFIED decision is only an end reason; camera and microphone are requested at run time, and AUDIO never asks for the camera | `VerificationCall.swift:12-13,423`, `CallPermissions.kt:15-21`, `VerificationCallView.swift:12-13` |
| No sensitive logging anywhere (grep) | — |

## 5. Platform parity

| Capability | iOS | Android |
|---|---|---|
| Hardware | Secure Enclave only | StrongBox, then TEE; software possible, refused by the server (D-16) |
| Offline key | SE ECDH key, secret derived in app memory on every use (D-01) | Imported HMAC key, non-exportable, per-use CryptoObject |
| Prompts for an offline v2 code | 1 (pre-evaluated `LAContext` used for both keys) | 2 (one per key) |
| Biometric-change handling | Reports `credentialInvalidated`, keeps state (D-07) | Deletes the key set and clears the registration |
| Attestation | App Attest only (SE key residency not attestable); entitlement undocumented (D-15) | Play Integrity (optional via `playIntegrityCloudProjectNumber`) plus Keystore key-attestation chains |
| Reported security level | Hard-coded `"SECURE_ENCLAVE"` | From `KeyInfo` (informational) |
| State storage | UserDefaults, multi-key, non-atomic (D-06) | SharedPreferences, single `commit()` |
| Push key | Keychain generic password (raw bytes readable by the app) | Keystore AES (decrypt) plus HMAC, non-exportable |
| Push receipt pinning | Not pinned (D-08) | Pinned |
| Prompt title/cancel configurable | n/a (system sheet) | `promptTitle`, `promptCancelText` |
| Cleartext | Loopback | Loopback, plus 10.0.2.2 opt-in |
| Response cross-check equality | Canonical equivalence (D-05); timestamps compared as `Date` | Exact; timestamps compared as strings |
| BIC check | `isValidBIC` function | `BIC` regex |
| Phrase whitespace | Unicode (D-10) | ASCII |
| Enrolment requires a device passcode | Implicit (`WhenPasscodeSet` keys fail to create) | Explicit `isDeviceSecure` check |
| API style | `async throws`, non-isolated class | `suspend`; needs a `FragmentActivity` for prompts |

## 6. Feature status

| Feature | Status | Notes |
|---|---|---|
| Hardware key generation and storage (iOS SE) | IMPLEMENTED / BLOCKED EXTERNAL | Needs an iPhone with Face ID and one with Touch ID, iOS 15 and the current iOS. Re-tagging SE keys via `SecItemUpdate` is unverified (ADR 0005) |
| Hardware key generation (Android StrongBox/TEE) | IMPLEMENTED / BLOCKED EXTERNAL | Needs a StrongBox device (Pixel 3+ with Titan M), a TEE-only device at API 28/29, and one at API 30+ |
| Biometric per-signature gating | IMPLEMENTED / BLOCKED EXTERNAL | Same devices; also the BiometricPrompt description truncation on OEM skins |
| WYSIWYS parsing and shared vectors | IMPLEMENTED (test runs UNVERIFIED) | `swift test` and `gradlew test` were not run here |
| Display text rules (new) | PARTIAL | D-02, D-03, D-04 |
| App Attest | IMPLEMENTED / BLOCKED EXTERNAL | Needs a paid Apple Developer team and the entitlement (D-15); a free Apple ID cannot provision App Attest |
| Play Integrity and key attestation | IMPLEMENTED / BLOCKED EXTERNAL | Needs a Play-installed build and a cloud project |
| Request signing | IMPLEMENTED | — |
| Certificate pinning | IMPLEMENTED (optional) | D-08; device check D1–D3 in the acceptance checklist |
| Offline confirmation v1 | IMPLEMENTED | iOS weakness D-01 |
| Offline v2 deferred signature and queue | IMPLEMENTED | iOS durability D-06; the SDK returns only the code, and provisional status is visible only on the bank side |
| Secure push | IMPLEMENTED | No replay protection (D-09); Notification Service Extension and FCM delivery BLOCKED EXTERNAL |
| Recovery phrase and protocol 2 | IMPLEMENTED | D-10 |
| Device replacement (two-phase) | IMPLEMENTED | — |
| Biometric-change handling | PARTIAL (iOS) | D-07 |
| Calls: signalling and controller | IMPLEMENTED (controller unit tests with fakes) | — |
| Calls: WebRTC media engines | IMPLEMENTED / UNVERIFIED | Unofficial binaries are a release blocker; DTLS assumed (D-14); needs a device plus TURN |
| Lost-device handling in the SDK | MISSING (by design) | Revocation is server- and bank-side; the SDK has no remote-wipe hook |

## 7. Tests: what they do and do not prove

- **Real behavioural tests** (pure logic, both platforms) cover shared vectors for the canonical parser, device protocols (request input, offline KDF, code, QR), secure push, recovery v2 and bank-trust fingerprints; plus amount formatting, offline-queue outcomes and age-out, key-slot promotion (`KeySlotsTest`, with an in-memory store), config validation including pin format, and the call controller state machine (`VerificationCallController*`, with fake relay and engine).
- **No test touches** Keystore, the Secure Enclave, BiometricPrompt, LAContext, App Attest, Play Integrity, OkHttp pinning, `CertificatePinning.Delegate`, `KeyManager` (either platform), `NEXUSSignSDK` flows or the WebRTC engines. Android tests are plain JVM tests: no `android.*` imports, no Robolectric, and `RecoveryPhraseTest` uses the internal wordlist overload.
- **A reader must not conclude** from these tests that keys are hardware-backed, that each signature needs a biometric, that invalidation works, that the prompt shows the text, that pinning rejects a wrong chain, that attestation verifies, or that calls are encrypted. Each of these needs the device tests named in sections 3 and 6.

