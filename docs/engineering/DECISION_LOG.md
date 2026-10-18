# Decision log

Engineering decisions of the 2.0.0 remediation. Newest last. Each entry names the finding it serves (forensic inventory 2026-10-16, `docs/audit/forensic-inventory/2026-10-16/11_FINDINGS_REGISTER.csv`).

## D-001 Local git snapshot instead of a GitHub clone (FI-009)

The working copy had no `.git` and GitHub is not reachable from this environment. A local repository was created (`baseline/2026-10-16` = `885d053`, work on `remediation/2.0.0`) so every change is a reviewable commit. It is not a GitHub commit. Before merging, the owner applies the branch as a patch series onto the GitHub head and resolves differences (the GitHub head is expected to contain `auth-core/package-lock.json`, which this copy lacks).

## D-002 No locally generated lockfile (FI-009)

The npm registry is blocked here. The dependencies used for testing were built from their GitHub sources; writing a `package-lock.json` from them would produce integrity hashes that do not correspond to registry tarballs. FI-009 stays open until a lockfile generated with `npm install` against the registry is committed.

## D-003 Expiry: report at read time, persist by a sweep (FI-013)

Read paths compute the reported state (`reportedState`), so no client sees `PENDING_USER` after `expiresAt`. A sweep (`FOR UPDATE SKIP LOCKED`, safe with several instances) persists `EXPIRED`, closes the plan and open verification sessions, writes the audit event with actor `system:expiry` and queues `authorization.expired`. The confirmation path and the sweep share `markExpired`, so the webhook is sent exactly once. Writing the state from a GET was rejected: reads must not take row locks.

## D-004 Outcome webhooks carry the chain head (FI-019, partial)

`authorization.verified` includes the evidence position and the chain head at sealing time, in the same transaction. A bank that stores these heads can detect tail truncation with `verify-evidence.mjs --expect-head`. Storing heads remains the bank's responsibility; FI-019 stays open for an independent checkpoint store.

## D-005 Webhook destination lookup uses the caller's transaction

Found during batch 1: the new webhooks are queued inside transactions that hold row locks. `enqueueWebhook` looked up the destination with a second pool connection; under 100 concurrent offline-code submissions (`invariants.test.mjs`) the pool was exhausted by transactions waiting for the lock and the run took 55 s with failed requests. The lookup now uses the transaction's connection. Earlier callers (`credential.replaced`, bank commit) had the same latent pattern.

## D-006 Demo pairing code (FI-016)

The demo bank's `/app/*` routes require an 8-digit code shown on the operator page and printed at start; ten wrong codes replace it. This is a demo control only: the demo bank stands in for a bank backend whose app sessions are authenticated by the bank's own login. Both demo apps ask for the code.

## D-007 Provider results are ES256 JWS checked by Auth Core (FI-002)

Options considered: (a) keep trusting the mTLS gateway; (b) HMAC with a secret shared with the bank; (c) asymmetric provider signatures with keys registered by the Auth Core operator. (a) is the defect. (b) would let whoever holds the bank-side secret forge results, the same trust as (a). (c) separates the parties: the bank gateway transports, the provider signs, the Auth Core operator decides which keys count. ES256 only, compact JWS, no keys carried in the token, kid lookup scoped to the bank. The claims bind the result to bank, session, authorization, transaction hash, credential and the session nonce the device received, with a lifetime of at most 600 s and a single-use `jti`. This is a breaking change of the completion endpoint, accepted because the old body could not be made safe.

## D-008 Channels exist only where a verifier exists (FI-017)

`audioAvailable`/`videoAvailable` defaulted to true, so plans escalated into channels no one could verify. A channel is now available when the bank has an active provider key for it or operator verification enabled; request flags can only remove channels. A requirement that cannot be met is refused at creation (409) instead of producing an authorization that can never complete.

## D-009 Sandbox keeps its simulated provider path

`sandbox/` is a Python reference server for integrators that simulates audio and video providers through an HMAC-signed webhook (`sandbox/README.md`). It is not changed in this batch and does not implement verification result v1; this difference is listed in `REMAINING_RISKS.md` until the sandbox is aligned.

## D-010 WebRTC with signalling relayed by Auth Core; operators in the admin console (FI-001, ADR 0017)

Default chosen without a paid provider and inside the bank's infrastructure: WebRTC (DTLS-SRTP by the stacks, no custom crypto), signalling over the existing authenticated HTTPS APIs with a long poll (no WebSocket dependency), the bank's coturn with per-session TURN REST credentials, operators answering in the admin console. External providers remain possible through signed result tokens (D-007). Recording is out of scope. Pending owner decisions: the WebRTC binary used in the SDKs, operator staffing, whether a provider is used for VIDEO.

## D-011 Declined and unanswered calls are neither success nor failure

A customer who declines or an operator queue that does not answer verifies nothing. Treating it as FAILED would let call availability reject payments; treating it as success would bypass the step. The plan returns to PENDING, three sessions per channel and authorization at most, then the bank escalates or cancels.

## D-012 ICE candidates are buffered around descriptions

Found by the real-media test: a peer gathers candidates as soon as it sets its local description, so its candidates can be relayed before its offer or answer, and the other side cannot apply a candidate before the remote description. Senders hold candidates until their description is posted; receivers hold candidates until the remote description is applied. The SDKs must follow the same rule.

## D-013 Account first, 140 characters, no padding (FI-003)

The system biometric prompt (iOS `LAContext` reason, Android `BiometricPrompt` description) has limited room and the platforms truncate long text at the end. Before: `name · iban`, values up to 512 characters, so a long name could leave the IBAN outside the visible part. Options: (a) shorten names on the device, which shows something other than what is signed; (b) a lower server-side limit only; (c) put the account identifier first and lower the limit to ISO 20022 Max140Text. Chosen (c): the account appears before anything a payer name can push away, and every value is still shown verbatim. Leading and trailing space separators and empty values are refused, because they change what is seen without changing what is read. Breaking for banks that send longer names (400 at creation); in-flight authorizations with longer values are refused by updated SDKs (`invalid_value`) and must be re-issued. The full prompt text on real devices remains a device check.

## D-014 Certificate pinning is opt-in, with at least two pins (FI-006)

Pinning protects enrolment and signed requests against a MITM holding a certificate from a trusted CA. A mandatory pin would lock out every app whose bank rotates its server key without shipping an update, so pins are a configuration of the bank app: SPKI SHA-256 in the OkHttp form on both platforms, at least two distinct pins (current and backup) when set, https only. Empty keeps the platform validation only. On iOS the system trust evaluation runs first, then the chain must contain a pinned key.

## D-015 WebRTC binaries: development approval, pinned, release blockers recorded (ADR 0017)

Owner decision of 2026-10-18: proceed with conditional integration of `io.github.webrtc-sdk:android` and `stasel/WebRTC` for development; no production approval. Pinned exactly: Android `150.7871.01` (newest milestone published), iOS `153.0.0` (newest release with a named source commit and checksum found; `155.0.0` exists). Evidence, licence findings and the open items TPM-1 to TPM-7 are in `THIRD_PARTY_MEDIA.md`; they are release blockers for gate G7. Both are isolated in optional modules (`android-sdk-calls`, `ios-sdk-calls`) so the core SDKs stay free of WebRTC.

## D-016 Signalling rules enforced by Auth Core, atomically

The relay previously accepted any signal type from either party. It now enforces, in one Redis script per message: offers only from the device and only when the previous offer is answered (one outstanding offer, which also makes ICE restart glare-free); answers only from the operator and only for an outstanding offer; candidates only after the sender's own description; nothing after the sender's bye. A client-chosen `messageId` makes a retried POST idempotent (200 with the original `seq`). Keys of a call share one Redis Cluster hash tag. HTTP replays are already refused by the device signature nonce and the admin session; the messageId only covers honest retries.

## D-017 Closure is announced by the server

A party should not keep a camera open on a session that has ended elsewhere (decision, cancel, expiry sweep, authorization confirmed or rejected, credential revoked). Every long poll checks the session at most every 2 s and relays one `bye` from `server` with the reason. This needs no hook in each code path that can close a session.

## D-018 Operator hang-up closes the session

Before, an operator who hung up left the session open and the customer waiting until expiry. `POST /admin/api/verification-calls/{id}/release` (claiming operator only) cancels the session like a customer cancel: nothing verified or failed, plan back to PENDING, audit `verification_session_cancelled` with `by: admin:<user>`, and the device receives `bye operator_left`. The customer may open a new session (attempt limit applies).

## D-019 Call state machine in the core SDKs, media behind an interface

The device-side rules (offer first, candidate buffering both ways, duplicate and stale messages ignored, ICE restart after a drop with a limit, endings mapped from bye reasons, local expiry, release exactly once, retries with the same messageId) are the same on both platforms and testable without WebRTC. They live in the core SDKs (`VerificationCallController`); libwebrtc is reached only through `CallMediaEngine`, implemented by the call modules with the native APIs. A JVM test runs the Kotlin controller against a real Auth Core with scripted media (`CallConformanceTest`); that proves protocol conformance, not media.

## D-020 Only VP8 and VP9 are negotiated

The WebRTC patent grant does not cover H.264/H.265. Both call modules wrap the default encoder and decoder factories so that only VP8 and VP9 are offered and accepted. This uses the long-standing factory interfaces rather than per-transceiver codec preferences, which are newer API.

## D-021 Real kotlinx-serialization in the local Android JVM run

The four SecurePushTest failures of the baseline came from the hand-written serialization stub. Gradle 8.14.3 ships kotlinx-serialization 1.6.2 (the SDK declares 1.6.3, same API); with it and the serialization compiler plugin from kotlinc, the SDK's JVM tests pass in full. Android APIs (Keystore, BiometricPrompt, OkHttp, WebRTC) remain stubs; this is still not an Android build.

## D-022 Master key ring with key IDs in the ciphertext (FI-005)

Options: (a) wrap the master keys in the HSM (PKCS#11 decrypt per use); (b) key IDs and a ring of current plus previous keys, with an offline re-encryption tool; (c) both. Chosen now: (b), because it is independent of the HSM vendor and testable here, and it is the precondition for (a) anyway: without key IDs no key can be retired. The key ID is derived from the key (SHA-256 prefix), so operators cannot mislabel it. Associated data is unchanged. The credential trigger accepts a new offline key ciphertext only inside the tool's transaction (`nexus.secret_rewrap`), and only if presence does not change; the application could set the flag too, but it already holds the master key, so no new capability arises. HSM wrapping (a) remains open (REMAINING_RISKS R-05).

## D-023 Offline codes: a deployment cap instead of a protocol change (FI-004)

A short code typed by a person cannot carry an asymmetric signature, so the server-side forgery risk is inherent. Limiting the amount per currency in the deployment configuration bounds the harm and keeps the database out of the decision. A deferred device signature uploaded later would make offline confirmations verifiable; it is recorded as an option for the owner (ADR 0003 amendment), not implemented.

## D-024 Device request nonces in PostgreSQL (FI-008)

Options: Redis `WAIT` for synchronous replication (depends on the Redis deployment and fails open on timeout), or PostgreSQL with a primary key. PostgreSQL already holds all durable state, so the nonce store inherits its replication and backup guarantees. Cost: one insert per device request; expired rows are deleted by the existing sweep. Redis remains available as `DEVICE_NONCE_STORE=redis` outside production for comparison. BOOTSTRAP token consumption stays in Redis (REMAINING_RISKS R-06).

## D-025 Every chain head goes to the bank (FI-019)

Heads were delivered only with confirmations; enrolment and recovery records were not covered and the bank had no way to check a head's origin. Now every appended record queues `evidence.appended` in the same transaction (outbox), with the HSM seal of the head. The bank's copy is the independent store; the verifier checks exports against all retained heads. An external timestamping or transparency log (FI-018) is not added.

## D-026 Metrics behind a bearer token (FI-030)

A separate port would need deployment changes in every environment; a bearer token on the existing route is enough to keep bank systems behind the gateway from reading operational metrics. Required in production.
