# Device acceptance checklist

What has to be shown on physical phones before gate G5 can pass. Nothing in this list has been executed: this environment has no Xcode, no Android SDK and no devices. Record every run in the table at the end, with device, OS version, app build (commit) and the result of each item.

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

## F. Offline confirmation

| # | Check | Pass when |
|---|---|---|
| F1 | QR challenge within the cap | Code accepted |
| F2 | Above `OFFLINE_CONFIRMATION_MAX_AMOUNT` | No QR offered (409); device signature works |

## G. Recovery and replacement

| # | Check | Pass when |
|---|---|---|
| G1 | Recovery phrase set-up and recovery on a second phone | Old credential revoked; new one `ACTIVE`; evidence chain verifies |
| G2 | Device replacement with a replacement token | As documented |

## Results

| Date | Tester | Device | OS | App commit | Items passed | Items failed | Notes |
|---|---|---|---|---|---|---|---|
| — | — | — | — | — | — | — | No run recorded |
