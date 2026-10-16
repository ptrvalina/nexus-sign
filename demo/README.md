# Demo on a real phone

Demo host apps for iPhone and Android and a demo bank backend for trying NEXUS-SIGN on a real phone: the phone enrols with Auth Core, the demo bank sends a payment, and the customer signs it on the phone with Face ID, Touch ID or the fingerprint. The signing key is created by the SDK in the Secure Enclave (iPhone) or the Android Keystore, StrongBox when the phone has it, and never leaves the phone.

| Part | Where | Role |
|---|---|---|
| Auth Core | `auth-core/scripts/run-local.sh`, port 8080 | The service, in development mode |
| Demo bank | `demo/bank-backend/demo-bank.mjs` | The bank's backend: holds the OAuth client, creates the NEXUS ID, issues BOOTSTRAP tokens, creates payments |
| iPhone app | `demo/ios`, Xcode project | The bank's app with the iOS SDK |
| Android app | `demo/android`, built by CI job `android-demo` | The bank's app with the Android SDK |

The demo bank listens on two ports, both on `127.0.0.1`:

| Port | For | Serves |
|---|---|---|
| 8090 | The computer's browser | Operator page: send a payment, see its status and the customer's evidence chain |
| 8091 | The phone | The app's calls to its bank (`/app/*`) and the Auth Core endpoints a device calls (`/v1/mobile/*`, recovery completion, push receipts), forwarded unchanged. The bank API and the admin console are not reachable on this port |

The phone reaches port 8091 over the USB cable on Android (`adb reverse`) and over HTTPS on the home Wi-Fi on iPhone. The SDKs accept plain HTTP only for `127.0.0.1` and `localhost`, so an iPhone, which has no `adb reverse`, needs an HTTPS address.

Development settings apply: software HSM, device attestation not required (`REQUIRE_VALID_ATTESTATION=false`). On iPhone, App Attest needs a paid Apple Developer membership; with a free Apple ID the SDK reports that attestation failed and Auth Core stores the credential with attestation status `UNKNOWN`. On Android without Play Integrity (a Google Cloud project) Auth Core does not verify the Keystore attestation either. In both cases the keys are still hardware keys and every payment is signed by them; what is missing is the server-side proof of where the key lives.

## Start the servers (both phones)

1. Auth Core: `cd auth-core && bash scripts/run-local.sh`.
2. In a second terminal, the demo bank: `node demo/bank-backend/demo-bank.mjs`. It reads the bank client secret from `~/nexus-local-credentials.txt`.
3. Open the operator page on the computer: `http://localhost:8090/`.

The demo app's calls to the demo bank (`/app/*`) need the pairing code shown on the operator page: anyone who can reach the device port could otherwise obtain an enrolment or replacement token for the demo customer (FI-016). The code changes at every start and after ten wrong attempts. The demo bank holds no real customer data; do not leave the device port reachable from a network after the demo.

`run-local.sh` starts every time with an empty database. After restarting it, restart the demo bank and tap "Зарегистрировать телефон заново" in the app.

## iPhone

Needs a Mac with Xcode 15 or later, a free Apple ID, and an iPhone with iOS 15 or later, a passcode and Face ID or Touch ID set up.

1. HTTPS on the home Wi-Fi. The iPhone and the computer running the demo bank must be on the same Wi-Fi; nothing is exposed to the internet.
   - Find the computer's Wi-Fi IPv4 address (Windows: `ipconfig`, "Wireless LAN adapter Wi-Fi" → IPv4 Address), for example `192.168.1.23`.
   - Create the certificate and start the demo bank with HTTPS on the device port:

     ```bash
     bash demo/bank-backend/make-cert.sh 192.168.1.23
     node demo/bank-backend/demo-bank.mjs --https
     ```

   - On Windows with WSL, forward the Wi-Fi port 8443 to the demo bank and allow it through the firewall (PowerShell as administrator; remove both after the demo with `netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=8443` and `Remove-NetFirewallRule -DisplayName "NEXUS-SIGN demo 8443"`):

     ```powershell
     netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=8443 connectaddress=127.0.0.1 connectport=8091
     New-NetFirewallRule -DisplayName "NEXUS-SIGN demo 8443" -Direction Inbound -Protocol TCP -LocalPort 8443 -Action Allow
     ```

     On a Mac or Linux machine without WSL, start the demo bank with `DEMO_DEVICE_PORT=8443` and `DEMO_DEVICE_HOST=0.0.0.0` instead.
   - Install the certificate authority on the iPhone: send `demo/bank-backend/tls/ca.crt` to the iPhone (AirDrop from the Mac, or mail it to yourself and open it in Mail), then Settings → Profile Downloaded → Install, and Settings → General → About → Certificate Trust Settings → turn on "NEXUS-SIGN Demo Local CA". Remove the profile after the demo (Settings → General → VPN & Device Management).
   - The server address for the app is `https://192.168.1.23:8443` (with your IP). Check it in Safari on the iPhone: `https://192.168.1.23:8443/app/pending` must show `{}` without a certificate warning.

   Where Cloudflare is reachable, a quick tunnel gives an HTTPS address instead, without a certificate: `cloudflared tunnel --url http://127.0.0.1:8091` (with the demo bank started without `--https`).
2. On the Mac, get the repository (`git clone`), open `demo/ios/NEXUSSignDemo.xcodeproj` in Xcode and wait until the `NEXUSSign` package is resolved.
3. Xcode → Settings → Accounts: add the Apple ID. Select the target NEXUSSignDemo → Signing & Capabilities → Team: your Personal Team. If Xcode says the bundle identifier is not available, change it to something unique, for example `com.<yourname>.nexussign.demo`.
4. Connect the iPhone by cable, unlock it and choose it as the run destination. On iOS 16 or later turn on Settings → Privacy & Security → Developer Mode (the iPhone restarts). Press Run.
5. The first launch is refused until the developer is trusted: on the iPhone, Settings → General → VPN & Device Management → your Apple ID → Trust. Run again.
6. In the app, enter the server address and the 8-digit pairing code shown on the operator page (and printed by the demo bank at start), tap "Подключиться", then "Зарегистрировать телефон".
7. On the operator page, send a payment. Within a few seconds it appears in the app; check the amount and the beneficiary, tap "Подтвердить Face ID / Touch ID" and confirm. The operator page shows the payment as confirmed by signature; the admin console (`http://localhost:8080/admin/`) shows the credential, the authorization and the audit trail.

With a free Apple ID the app runs for seven days; run it again from Xcode after that.

## Android

Needs an Android 9 or later phone with a screen lock and a fingerprint or face enrolled, a USB cable, USB debugging (Settings → About phone → tap "Build number" seven times; then Developer options → USB debugging), and `adb` on the computer the phone is plugged into (on Windows: `winget install --id Google.PlatformTools -e`, then a new PowerShell window).

1. Get the APK: in the repository on GitHub, Actions → the latest CI run on `main` → artifact `nexus-sign-demo-apk`; unzip it.
2. Plug in the phone, allow USB debugging on the phone, and run:

   ```
   adb devices
   adb install -r app-debug.apk
   adb reverse tcp:8091 tcp:8091
   ```

   `adb reverse` lasts until the cable is unplugged; run it again after reconnecting.
3. On the phone, open NEXUS-SIGN Demo, enter the pairing code from the operator page and tap "Зарегистрировать телефон".
4. On the operator page, send a payment, then confirm it in the app with "Подтвердить биометрией".

To build the APK locally (JDK 17 and the Android SDK): `cd demo/android && sh ../../android-sdk/gradlew assembleDebug`; the APK is `app/build/outputs/apk/debug/app-debug.apk`.
