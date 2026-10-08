# NEXUS-SIGN Sandbox

Non-production environment for bank workshops, integration rehearsals and control demonstrations. It speaks the same transaction authorization protocol v1 as Auth Core and the mobile SDKs, with synthetic data only. The release is the repository's `VERSION`.

Nothing here authorizes a real transaction, and the sandbox is not a production system; its boundary is described [below](#security-boundary).

## Run

Requirements: Python 3.10 or newer. Standard library only; no packages, no network access.

```bash
./scripts/run.sh            # macOS / Linux
```
```powershell
.\scripts\run.ps1           # Windows PowerShell
```

Open **http://127.0.0.1:8787**. Use `127.0.0.1` or `localhost`: browsers enable WebCrypto only in a secure context, and these addresses count as one. A LAN IP over plain HTTP does not.

### Settings

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `8787` | Listening port |
| `HOST` | `127.0.0.1` | Listening address; any other address requires `SANDBOX_ACCESS_CODES` |
| `SANDBOX_ACCESS_CODES` | empty (local mode) | `name:code,name:code`; enables hosted mode, one workspace per code |
| `SANDBOX_SESSION_SECRET` | random per process | Signs session cookies; set it so sessions survive a restart |
| `SANDBOX_SESSION_TTL_SECONDS` | `43200` | Session cookie lifetime |
| `SANDBOX_TRUST_PROXY` | off | `1` behind the bundled reverse proxy, so rate limits use the client address |
| `SANDBOX_INSECURE_COOKIES` | off | `1` drops the `Secure` cookie flag for plain-HTTP testing only |
| `SANDBOX_MAX_AUTHORIZATIONS` | `300` | Authorizations per workspace before a reset is required |
| `SANDBOX_PROVIDER_WEBHOOK_SECRET` | random per process | Set only to send provider webhooks from your own test harness |
| `SANDBOX_ACCESS_LOG` | off | `1` prints one line per request |

## Hosting for banks and partners

In hosted mode every guest gets an access code that opens a private workspace. Deployment is a container behind Caddy with an automatic HTTPS certificate: see [HOSTING.md](HOSTING.md).

## Tests

```bash
./scripts/test.sh           # or: python3 -m unittest discover -s tests -v
```

The suite runs in about two seconds:

- `tests/test_protocol.py` checks the canonical encoder and strict parser against the shared vectors (`auth-core/test-vectors/signed-payload-v1.json` and `device-protocols-v1.json`, read in place, so the tests run from a full repository checkout), with the same rejection reasons as the SDKs. It also checks the ECDSA implementation, including signatures made by OpenSSL, WebCrypto and the JVM (`tests/vectors/ecdsa-interop.json`).
- `tests/test_api.py` starts the server and runs every row of the [control test matrix](#control-test-matrix) through the HTTP API.
- `tests/test_hosted.py` covers hosted mode: access codes, workspace isolation, session cookies (code binding, server-side sign-out), the rate limit on failed codes, and the refusal to listen publicly without codes.

## Using it

- **In the browser:** see the [demonstration script](#demonstration-script).
- **From a script or another service:** see `openapi.yaml`. `tools/device_simulator.py` plays the phone from the command line:

```bash
python3 tools/device_simulator.py enrol                # prints credentialId
# create an authorization with that credentialId (POST /api/v1/authorizations), advance to SIGNATURE, then:
python3 tools/device_simulator.py sign <authorizationId>
# hosted sandbox: add --base=https://<domain> --token=<access code>
```

On a hosted sandbox, send the access code as `Authorization: Bearer <code>` on every API call.

## Relation to the production API

The payload, its hash and the signature are identical to production. `GET /api/v1/authorizations/{id}` returns the same fields as `GET /v1/mobile/authorizations/{id}` in Auth Core, and the real Android SDK validator accepts it.

The control endpoints are sandbox-only: `advance`, `fault`, `clock`, `reset` and device enrolment. In production, enrolment goes through `/v1/mobile/bootstrap` with platform attestation, and the bank authenticates with OAuth and mTLS.

To test against a real Auth Core, use `auth-core/scripts/e2e-smoke.mjs`.

## Layout

```
server/main.py        HTTP API, state machine, evidence
server/protocol.py    v1 canonical encoding and strict parser (mirror of the SDKs)
server/p256.py        ECDSA P-256 / SHA-256, standard library only
web/                  UI; the browser is the device (WebCrypto)
server/access.py      access codes, workspaces and sessions (hosted mode)
tools/                device simulator, access-code generator
deploy/               docker compose + Caddy (HTTPS) for hosting
Dockerfile            container image
tests/                protocol vectors and API tests
config/policy.json    policy profile TXN-AUTH-v4
```

## Security boundary

| Component | Implementation |
|---|---|
| Authorization API and state machine | Real logic, in-memory state, lost on restart or reset |
| Canonical authorization object v1 | Real, byte-identical to Auth Core and the SDKs (shared vectors) |
| Device key and signature | Real ECDSA P-256; the key is generated in the browser by WebCrypto, is non-extractable and never sent to the server |
| Signature verification | Real, `server/p256.py`; cross-checked against signatures made by OpenSSL, WebCrypto and the JVM (`tests/vectors/ecdsa-interop.json`) |
| "What you see is what you sign" check | Real, same rules as the SDKs |
| Attempt limit, expiry, one-time use, idempotency | Real |
| Adaptive verification policy | Real rules; escalation only, no downgrade |
| Offline confirmation | Real ECDH, HKDF and code derivation, identical to the SDKs; the browser's key-agreement key is non-extractable, the derived code key exists in page memory (the SDKs keep it in hardware). The bank screen shows a real QR code; the browser device reads the payload directly instead of a camera |
| Webhooks | Real HMAC over the raw body, timestamp window and event replay protection |
| Evidence ledger | Real hash chain and seals, in memory. Signed records carry the exact signed bytes and the device key, so the customer's signature is re-verified with the chain |
| HSM | Simulated by an ephemeral P-256 key, regenerated on every start |
| Audio and video providers | Simulated; results go through the HMAC-signed webhook path |
| Push delivery, bank commit | Simulated |
| Risk engine | Decision chosen by the operator in the UI |

The server never holds a private key that can sign an authorization. For offline confirmation it holds, as Auth Core does, the agreed code key; that is why an offline code is recorded as `OFFLINE_CODE` rather than as a signature.

Outside the sandbox: real customer data, accounts and balances, payment networks, telecom identifiers, real calls or video sessions, production keys, HSMs and platform attestation (Apple App Attest, Google Play Integrity).

Differences from production:

- Device enrolment takes a public key without attestation. Production requires `/v1/mobile/bootstrap` with a session-bound attestation.
- Local mode has no authentication and binds 127.0.0.1 only; without access codes the server refuses to bind a public interface. Hosted mode uses per-guest access codes, each with an isolated workspace; HttpOnly, Secure, SameSite=Strict session cookies bound to the current code and revoked on sign-out; and a per-address limit on failed codes for both the sign-in form and `Authorization: Bearer`. Production uses OAuth 2.0 client credentials with mTLS for the bank and device-signed requests for the device.
- The sandbox ECDSA signer is not constant time. It is used by the tests, the CLI simulator and to seal evidence with the ephemeral sandbox key; none of these keys protects anything real, and signature verification uses only public data.

The UI is labelled SANDBOX / NON-PRODUCTION. A result shown here is a control-model result, not a production certification or a penetration-test conclusion.

## Control test matrix

Every row is an automated test in `tests/` and can be shown in the UI.

| Control | Scenario | Expected result | Test |
|---|---|---|---|
| Protocol parity | Payload from the sandbox | Accepted by the SDK validator: 15 fields, hash matches, response matches bytes | `Protocol` |
| Canonical form | Shared vectors (valid, invalid and response mismatch cases) | Byte-for-byte identical; same rejection reasons as the SDKs | `test_protocol.CanonicalVectors` |
| Idempotency | Same key and body; same key, different body; same transaction reference, new key | Same authorization (200); 409 `IDEMPOTENCY_KEY_REUSED`; 409 `TRANSACTION_REFERENCE_REUSED` | `Idempotency` |
| Transaction binding | Altered payload signed; signature from another authorization; signature by another enrolled device | Rejected (`signature_verification_failed`; nonce and ID are in the signed bytes) | `TransactionBinding` |
| One-time use | Valid signature submitted again | 409 `AUTHORIZATION_NOT_PENDING` | `TransactionBinding` |
| Device-only signing | Control plane tries to advance past SIGNATURE | 409 `DEVICE_SIGNATURE_REQUIRED` | `TransactionBinding` |
| Step order | Signature before PUSH/AUDIO/VIDEO complete | 409 `VERIFICATION_STEPS_INCOMPLETE` | `TransactionBinding` |
| WYSIWYS | Response shows a different amount than the signed bytes | Device refuses to display or sign | UI "Forged display"; `test_response_mismatch_cases` |
| Offline confirmation | QR read without network, code typed on the bank screen; guessed code; code of another authorization, QR for another device | VERIFIED with `OFFLINE_CODE`; guesses count against the 5-attempt limit; rejected, the device refuses the QR | UI "Confirm offline (QR code)", "Wrong offline code"; `OfflineConfirmation` |
| Push fallback | Push timeout | AUDIO inserted before SIGNATURE | `AdaptiveVerification` |
| High risk | Amount ≥ threshold or `STEP_UP` | PUSH → AUDIO → VIDEO | `AdaptiveVerification` |
| Anti-downgrade | AUDIO provider failure; VIDEO provider failure | VIDEO required, signing blocked until it passes; REJECTED `VERIFICATION_FAILED` | `AdaptiveVerification` |
| Risk block | Risk decision BLOCK | REJECTED `RISK_BLOCK`; cannot be advanced, signed or committed | `Risk` |
| Signature abuse | 5 invalid signatures | At the limit, REJECTED `SIGNATURE_ATTEMPT_LIMIT` | `SignatureAbuse` |
| Expiry | Signing after `expires_at`; commit more than 5 min after verification | 410 `AUTHORIZATION_EXPIRED`; 409 `VERIFICATION_TOO_OLD` | `Expiry` |
| Webhooks | Invalid HMAC or altered body; timestamp outside ±300 s; same event ID twice | 401; 401; 409 `WEBHOOK_REPLAY` | `ProviderWebhook` |
| Bank orchestration | Verified authorization | COMMITTED once; second commit 409 | `HappyPath` |
| Evidence | Full flow | CREATED → VERIFIED → COMMITTED, hash-linked, seals verify; tampering detected | `Evidence` |
| Input handling | Invalid amounts, currency, beneficiary or enum; oversized body, malformed JSON, invalid public key | 400 (connection kept); 413 / 400 | `InputHandling` |
| Static files | Path traversal (`/web/../../etc/…`, encoded variants) | 404; only the 3 UI files are served | `StaticFiles` |
| Browser hardening | UI response | CSP `default-src 'self'`, `nosniff`, `frame-ancestors 'none'`; all dynamic text inserted as text | `StaticFiles` |

## Demonstration script

About 15 minutes. Start with **Reset environment** so the event stream is empty.

1. **Boundary.** Point out `SANDBOX / NON-PRODUCTION` and the panel **This device**: the browser has generated a P-256 key that cannot be exported, even by the page's own script; only the public key went to the server.
2. **Standard transfer.** Create one; the panel shows **PAYLOAD VERIFIED**, with amount, beneficiary, reference and expiry parsed from the exact bytes the key will sign and the SHA-256 of those bytes. **Run PUSH**, **Approve on device (sign)**, **Commit at bank**.
3. **Attacks at the signing step.** Create another transfer and run PUSH. **Forged display**: the device refuses. **Tampered payload**: the server rejects the signature (attempt 1/5). **Signature replay**: rejected, because the authorization ID and nonce are signed. **Approve on device** then still passes.
4. **Confirmation without network.** Advance a transfer to the signature step and press **Confirm offline (QR code)**. The code covers the hash of exactly these bytes; **Wrong offline code** uses up the same five attempts. Evidence marks the record `OFFLINE_CODE`: bound to the bytes, but not a signature a third party can verify.
5. **Adaptive verification.** **Push timeout** inserts AUDIO; an amount of 50,000.00 or more, or risk `STEP_UP`, gives PUSH → AUDIO → VIDEO; an AUDIO failure adds VIDEO and blocks signing until it passes; a provider failure at VIDEO rejects the authorization.
6. **Risk block and expiry.** Risk decision **BLOCK** rejects at creation. **Clock +5 min** expires a transfer.
7. **Evidence.** Show a record (payload hash, signature, policy version, verification path, link to the previous record) and press **Verify chain**: every hash, seal and the customer's signature are re-verified. Whoever holds the sealing key can re-seal a record, but cannot make the customer's key sign different terms. `GET /api/v1/evidence` exports the chain with the sealing public key; for Auth Core, `npm run verify-evidence` checks the same offline.
8. **Bank boundary.** The bank remains the system of record. In production the device is the bank's app with the SDK (Secure Enclave, StrongBox); the payload and the signature are the ones shown here.

To expose the sandbox beyond 127.0.0.1, use hosted mode behind HTTPS as described in [HOSTING.md](HOSTING.md).
