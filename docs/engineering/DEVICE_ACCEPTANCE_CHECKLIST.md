# Device acceptance checklist

What has to be shown on physical phones before gate G5 can pass. **Status 2026-10-18 (re-checked in phase 10): BLOCKED — nothing has been run on an iPhone or an Android phone.** Nothing in this list has been executed: this environment has no Xcode, no Android SDK, no physical devices and no TURN server reachable from a mobile network. Gate G5 stays FAIL/BLOCKED until the results table has entries. Record every run in the table at the end, with device, OS version, app build (commit) and the result of each item.

Minimum for phase 9 acceptance (each line is a checklist item below): camera and microphone permissions (E1); start and end of a call (E2, E3, E11, E12); operator refusal (E10); network loss and recovery, ICE restart (E7); TURN from an external and a mobile network (E8); app in background (E6); device revoked during a call (E18); session expiry (E13); repeated result (E23); forged result (E21); terms on the phone equal what the device signs (C1, E24); no recording (E22); release of camera, microphone and temporary resources (E25); offline confirmation v2 (F3–F8). Calls run inside the bank's app through the NEXUS-SIGN SDK (demo apps), with no separate app and no third-party branded service.

Setup: Auth Core and the demo bank on a computer ([demo/README.md](../../demo/README.md)), operator verification enabled (`verificationSetup.js operator local-bank AUDIO,VIDEO`), an operator account in the admin console, TURN reachable for tests across networks.

Minimum devices: one iPhone with Face ID (iOS 17 or later), one iPhone with Touch ID or iOS 15/16 if supported, one Android phone with StrongBox (Pixel 6 or later), one Android phone without StrongBox (TEE only), Android 9 (minSdk 28) if available.

## A. Build and install

| # | Check | Pass when |
|---|---|---|
| A1 | iOS demo builds in Xcode with the local packages `ios-sdk` and `ios-sdk-calls` | Build succeeds; `Package.resolved` shows stasel/WebRTC 153.0.0; record the resolved checksum |
| A2 | Android demo builds (`demo/android`, `assembleDebug`) with `android-sdk` and `android-sdk-calls` | APK built; record the SHA-256 of `io.github.webrtc-sdk:android:150.7871.01` from the Gradle cache |
| A3 | Release builds of both SDKs (`swift build -c release`, `assembleRelease`) | No warnings treated as errors; R8/ProGuard keeps `org.webrtc` |

## B. Enrolment and keys

| # | Check | Pass when |
|---|---|---|
| B1 | Enrolment with the pairing code | Credential `ACTIVE`; attestation `VERIFIED` (App Attest / Play Integrity and Keystore attestation) in a configuration with `REQUIRE_VALID_ATTESTATION=true` |
| B2 | Android key placement | StrongBox phone: `security_level` STRONGBOX; TEE phone: TEE; `REQUIRE_STRONGBOX` refuses the TEE phone |
| B3 | No lock screen / no passcode | Enrolment refused with the documented error |
| B4 | Biometric change after enrolment | Next approval fails with `credentialInvalidated` / `CredentialInvalidated`; re-enrolment works |

## C. Confirmation display (FI-003)

| # | Check | Pass when |
|---|---|---|
| C1 | Payment with a 140-character payee name and an IBAN | The system biometric prompt shows the IBAN in full on the first line, on every device and in portrait. Take screenshots |
| C2 | Same with the largest system font size | IBAN still visible; record what the prompt truncates |
| C3 | Host screen | Every beneficiary field shown in full, wrapped |
| C4 | Server refusal | A 141-character name or a padded value is refused when the payment is created (400) |

## D. TLS pinning (FI-006)

| # | Check | Pass when |
|---|---|---|
| D1 | Pins of the server key and a backup key configured | Requests succeed |
| D2 | MITM proxy with a user-installed CA (Android: network security config permitting user CAs in debug; iOS: profile-installed CA) | With pins: every SDK request fails; without pins: the documented platform behaviour |
| D3 | Pin of a rotated key only after a server key change | Requests succeed with the backup pin |

## E. Verification calls (FI-001, ADR 0017)

| # | Check | Pass when |
|---|---|---|
| E1 | Permissions | The app asks for microphone (and camera for VIDEO) only when the customer starts the call; declining shows the message and places no call |
| E2 | VIDEO call, same Wi-Fi | Operator sees and hears the customer, customer sees and hears the operator; the terms on the phone match the operator's panel; latency acceptable to the tester |
| E3 | AUDIO call | No camera activity (system indicator off) during the whole call |
| E4 | Indicators | The in-app indicator and the system indicator (iOS green/orange dot, Android privacy indicator) agree at every moment, including after mute and camera-off |
| E5 | Camera off / mute | Operator's view freezes or goes black / audio stops; system camera indicator goes off |
| E6 | Background | Home button during VIDEO: camera stops (system indicator off); back to the app: camera resumes unless turned off before |
| E7 | Network switch during the call (Wi-Fi → mobile data) | The call recovers within ~10 s by ICE restart, or ends with "connection lost" after two restarts; it never stays frozen without a state |
| E8 | Restrictive network (mobile data, operator on another network) | Connects through TURN; record the selected candidate type (`relay`) from the console's WebRTC internals |
| E9 | Operator VERIFIED | Call ends on both sides; the app enables the biometric confirmation; payment `VERIFIED`; evidence factor `method: OPERATOR`, `issuer` = operator |
| E10 | Operator FAILED | Payment `REJECTED`; app shows the result |
| E11 | Operator hangs up | App shows "ended without result"; a new call is possible (three sessions per channel) |
| E12 | Customer hangs up | Operator console shows the customer left; session `CANCELLED` |
| E13 | Nobody answers for 5 minutes | Session `EXPIRED`; app shows it; camera and microphone off |
| E14 | App killed during the call | Operator sees the call end within the session expiry at the latest; no camera or microphone use after the kill |
| E15 | Phone call (GSM) during the verification call | Audio routing is restored or the call ends cleanly; record behaviour |
| E16 | Bluetooth headset | Audio uses the headset; switching works |
| E17 | Battery and heat | 5-minute VIDEO call: record battery drop and device temperature warnings |
| E18 | Device credential revoked by the bank during a VIDEO call | Both sides receive the server's `credential_revoked`; camera and microphone stop within ~2 s; the app shows the end |
| E19 | Authorization confirmed elsewhere (e.g. online signature on another screen) during a call | Call ends with `authorization_closed` |
| E20 | Policy met only partly (VIDEO required, operator verified AUDIO only) | Biometric approval is refused by Auth Core until the required channel is VERIFIED |
| E21 | Forged, expired, replayed or other-transaction provider result tokens (if an external provider is used) | Refused; plan unchanged (server-side tests exist: `verification-results.test.mjs`) |
| E22 | No recording | Confirm no media files on the device (app container) and no media in Auth Core, Redis or logs; do not record the test session itself unless a separately approved test design requires it |
| E23 | Operator decision sent twice (double click, network retry in the console) | One decision recorded; the second is refused or ignored; the plan changes once |
| E24 | Terms on the phone during and after the call | The amount, currency, payee and IBAN on the phone's confirmation screen and biometric prompt equal the operator panel and the bank's own record; the bytes the device signs (`canonicalPayloadBase64`) carry the same values (compare with the evidence export after VERIFIED) |
| E25 | Resources after every ending (operator hang-up, customer hang-up, expiry, revocation, app kill) | Camera and microphone released (system indicators off), no WebRTC process or capture session left (Xcode Instruments / Android `dumpsys media.camera`), no temporary files in the app container |

## F. Offline confirmation

| # | Check | Pass when |
|---|---|---|
| F1 | QR challenge within the cap | Code accepted |
| F2 | Above `OFFLINE_CONFIRMATION_MAX_AMOUNT` | No QR offered (409); device signature works |
| F3 | v2 (`NXS2.`), phone in airplane mode: confirm, type the code | Bank sees `PROVISIONAL`; Android shows two biometric prompts with the transaction, iOS one; record what each prompt shows |
| F4 | Then switch the network on and start the app | `submitPendingOfflineSignatures()` delivers 1; authorization `VERIFIED`, evidence `OFFLINE_SIGNED`; `verify-evidence.mjs` passes |
| F5 | Cancel the second Android prompt after the first | No code shown; the stored signature is uploaded later and answered `RECEIVED` or 409; nothing is confirmed |
| F6 | Kill the app after the code, before going online | The signature survives the restart and is delivered |
| F7 | Old app (SDK 2.0.0-rc.2) with an `NXS2.` QR | QR refused (`invalid_qr`); no code |
| F8 | Revoke the device while a confirmation is provisional | Bank receives `authorization.offline_unsigned` (`credential_not_active`) |

## G. Recovery and replacement

| # | Check | Pass when |
|---|---|---|
| G1 | Recovery phrase set-up and recovery on a second phone | Old credential revoked; new one `ACTIVE`; evidence chain verifies |
| G2 | Device replacement with a replacement token | As documented |

## Results

| Date | Tester | Device | OS | App commit | Items passed | Items failed | Notes |
|---|---|---|---|---|---|---|---|
| — | — | — | — | — | — | — | No run recorded |
