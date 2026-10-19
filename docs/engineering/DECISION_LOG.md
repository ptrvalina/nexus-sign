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

## D-027 Master keys wrapped by an HSM key-encryption key (FI-005)

Checked first what the stack supports: pkcs11js exposes C_Encrypt/C_Decrypt with `CK_PARAMS_AES_GCM`, and SoftHSM 2.7.0 lists CKM_AES_GCM (encrypt and decrypt), CKM_AES_KEY_WRAP(_PAD) and CKM_AES_KEY_GEN; a probe confirmed AES-GCM with associated data, refusal of wrong associated data (CKR_ENCRYPTED_DATA_INVALID) and that a sensitive key's value cannot be read. Options: (a) envelope encryption, master keys wrapped by an HSM KEK and unwrapped into process memory at startup; (b) master keys as HSM objects and every secret operation in the HSM. Chosen (a): it removes plaintext keys from the configuration and from configuration backups, keeps the hot paths independent of HSM latency, and leaves the stored format unchanged so (b) remains possible. Startup fails closed. Production requires it. Residual: process memory and anyone with the PIN and HSM reach (KEY_MANAGEMENT.md). Validated on SoftHSM only; a vendor HSM may need `CK_PARAMS_AES_GCM_v240` or different attribute policy.

## D-028 FI-004: bound the residual risk now; the complete fix waits for the owner

Traced the protocol (docs/security/offline-confirmation-threat-model.md): without `K` no party, including a compromised bank backend or a database writer, gets a code accepted (tests). With `K` — database plus the device master key, or a running Auth Core — codes can be computed; that is inherent in a shared-key MAC. Added a per-credential daily ceiling next to the amount cap (both deployment-side, required in production) and made the master key HSM-wrapped (D-027), which removes the "database plus configuration" path. The complete correction is a deferred device signature, a protocol extension with SDK and evidence changes; it is written up for an owner decision, not implemented.

## D-029 FI-004: deferred device signature implemented as offline confirmation v2

The phase 8 instruction asked for the deferred signature to be designed and implemented without silently choosing a risky variant. Choices made, each the conservative option:

- **Format:** the existing canonical bytes and signing key, not a new signed structure; the bytes already bind every required field including the purpose (`domain`). A second format would be a second parser on three platforms.
- **When `VERIFIED`:** only with both the code and the signature. A code alone is `OFFLINE_PROVISIONAL`; a signature alone is stored, not used. Auth Core's commit flow needs `VERIFIED`, so a bank using it waits by construction. **Open for the owner and the banks:** whether a bank may execute on `PROVISIONAL` (its own systems can); the documentation recommends not to.
- **Default and production:** `deferred_signature` by default and required in production; v1 kept for development and existing data. Changing the default changes behaviour for every configuration that had offline confirmation enabled without setting the mode; recorded in the upgrade notes.
- **Old SDKs:** refused through the new QR prefix rather than left to produce codes that can never be completed.
- **Deadline:** 72 hours by default (1–720); after it, or when the credential or identity is no longer `ACTIVE`, the confirmation ends `OFFLINE_UNSIGNED`.
- **Late signatures:** never used after `OFFLINE_UNSIGNED`; audited with the verification result.

## D-030 Policy reference and version are immutable

While adding the v2 states to the authorization trigger: `policy_reference` and `policy_version` are part of the signed bytes but were not in the trigger's immutable list. A change was caught by the hash check at confirmation time, so no wrong confirmation was possible, but the row could be changed. Migration 022 adds both to the immutable fields.

## D-031 KEK must be generated in the HSM (FI-005)

The KEK check required `CKA_SENSITIVE` and not `CKA_EXTRACTABLE`. An AES key imported with `C_CreateObject` from a known value satisfies both, so a copy of the KEK could exist outside the HSM. Auth Core now also requires `CKA_LOCAL` and `CKA_NEVER_EXTRACTABLE` (test: imported KEK refused). `masterKeys.js create-kek` already generates such keys. Vendor HSMs set these attributes per the PKCS#11 specification; to be confirmed on the vendor HSM.

## D-032 Master keys stay in process memory (FI-005, not changed)

Assessed whether the application could stop holding the master keys: the stored format (`k1$keyId$iv$tag$ct`, AES-256-GCM, associated data per secret) is decryptable by an HSM with `C_Decrypt` and `CKM_AES_GCM` if the master key itself is an HSM object, so a per-operation HSM design (D-027 option b) is format-compatible. It requires importing each master key into the HSM as a non-extractable object (unwrap with the KEK; whether `C_UnwrapKey` accepts `CKM_AES_GCM` is vendor-specific), one HSM round trip per offline code, webhook delivery and admin login, and HSM availability on those paths. Not implemented in this phase: no vendor HSM to validate it, and it does not change the boundary for an attacker controlling the process (who can still ask the HSM). The per-use copy of `K` is now wiped after the comparison.

## D-033 FI-004: OFFLINE_PROVISIONAL is never an authorization to execute (owner decision, phase 9)

The phase 9 instruction settles the question left open in D-029: `OFFLINE_PROVISIONAL` does not authorize a bank operation; `VERIFIED` requires a valid signature of the enrolled device over the exact canonical bytes; production refuses code-only confirmation; v2 stays the default. Implemented as: no option to treat provisional as verified; `confirmed` flag in the bank's `GET` (true only for `VERIFIED`) and in the offline webhooks; the demo bank shows a payment as confirmed only for `VERIFIED` with `confirmed: true`; v1 needs `ALLOW_INSECURE_DEVELOPMENT=true` outside production. This is a technical authorization rule, not a statement about the legal effect of a signature.

## D-034 The bank commit re-verifies the evidence (FI-004, phase 9)

`requestCommit` used to trust `state = 'VERIFIED'`. The database trigger permits `PENDING_USER → VERIFIED` with any non-empty signature value, so a database writer could produce a row the commit accepted. Now the commit loads the single sealed `AUTHORIZATION` record and requires: valid HSM seal, binding to this authorization, credential, identity and stored terms, the same confirmation method as the row, a device signature (`DEVICE_SIGNATURE` or `OFFLINE_SIGNED`) that verifies with the key sealed at enrolment, and on a v2 deployment no `OFFLINE_CODE`. Cost: one seal and one ECDSA verification per commit. It does not help against a party controlling the running process.

## D-035 Service-level device check, tested without the HTTP layer

The phase 8 mutation removing the "same device" check in `submitDeferredSignature` survived because the route's scope check also refuses. A test now calls the compiled service function from a separate process, bypassing the routes, and shows that the service itself refuses (and that the same call with the bound credential succeeds). Both layers keep the check.

## D-036 Commit check covers the chain position; `confirmed` follows the evidence (phase 10)

A record with a genuine HSM seal could still be inserted next to the chain rather than appended to it (any party able to seal). The commit check now requires the sealed `chainSequence` and `previousEvidenceHash` to match the stored row and the predecessor. `confirmed` in the bank's `GET` was derived from the state column, so a database write produced `confirmed: true`; it is now true only when the same evidence check passes at read time, with `evidenceProblem` otherwise. It remains a value computed by Auth Core, not a cryptographic fact for the bank.

## D-037 Device parsers check ID and nonce formats (phase 10)

The protocol requires valid formats on the device; the parsers checked amount, currency and timestamps only. Added: lowercase UUIDs for `authorization_id` and `credential_id`, 9-digit `nexus_id`, 64-character lowercase hex `nonce`, on Android, iOS and in the sandbox, with vectors. Auth Core always issued these formats; the canonical encoding is unchanged, so no version change. Look-alike payee names remain valid (they are signed and shown as they are; FI-034).

## D-038 Evidence row metadata must equal the sealed payload (phase 11)

The HSM seal covers the sealed payload, not the columns of the row around it. The commit check and the `confirmed` flag compared the payload with the authorization row, but not the record's own `nexus_id` and `credential_id` columns with the payload: an owner-level change of those columns (the append-only trigger disabled) left the seal valid and a commit was accepted (reproduced on `2df8754`, `evidence-metadata-binding.test.mjs` 2–4). Every column that repeats a sealed value (`record_type`, `nexus_id`, `credential_id`, `authorization_id`, `chain_sequence`, `previous_evidence_hash`, `seal_key_id`, `schema_version`) must now equal it, strictly, in the commit check, in `confirmed` and in the enrolment check; the verifier checks the same for schema 3 exports (`credentialId`, `sealKeyId`, `schemaVersion` added). No schema change: a CHECK constraint cannot compare a column with JSONB written by the same insert any better than the check at the point of use, and would not stop the owner who disables triggers either. Columns that repeat values but are not used in any decision (`transaction_reference`, `signature` and other copies) are not part of the check.

## D-039 The enrolment cache covers only the ECDSA verification (phase 11)

`assertCredentialIntegrity` cached a verified enrolment by its evidence ID and skipped reading the row again, so a row changed after the first use was not seen (`evidence-metadata-binding.test.mjs` 8). The row is now read on every use, its payload and columns are checked every time; only the seal verification is cached, keyed by the exact evidence ID, hash, seal key ID and signature it was computed over.

## D-040 No second pool connection while the authorization row is locked (phase 11)

Under 20 parallel commit requests on an authorization whose evidence is refused, part of the requests ended in HTTP 500 (statement timeout waiting for the row lock): the request holding the lock read the credential and wrote the security event through the pool while the waiting requests held the remaining connections. Nothing was committed, but the answer was wrong and security events were missing for refused requests. The commit check now reads through its transaction, and the security events of a refusal are written after the transaction has ended (`evidence-metadata-binding.test.mjs` 10, 10b).

## D-041 Device trust is decided by the bank, outside Auth Core (phase 12)

A fully compromised Auth Core can enrol or substitute a device key, seal it with the real evidence key and accept confirmations signed by it; every Auth Core answer and the export are then positive (`bank-trust-compromise.test.mjs`, reproduced on `be3bee7`). Options compared:

1. Auth Core checks a bank approval before it accepts a confirmation. This runs inside the compromised component, so it adds nothing under this model. It would also need an API and a migration. Not chosen.
2. The bank countersigns the enrolment evidence, sealed back into the chain. The countersignature would have to be checked by the bank anyway; it adds a round trip and a format change. Not needed.
3. **A bank-signed approval of `(nexusId, credentialId, signing key fingerprint)` in the bank's own registry, and the bank's own execution decision over the export. Chosen.** It uses only data the bank already holds or can get from its app. No device protocol change and no Auth Core change.
4. Anchoring keys and heads outside Auth Core. Already in place (`--public-keys`, `--expect-head`, `--heads`); the decision now requires the pinned keys and uses the heads.

The decision is `scripts/lib/bankTrust.mjs`, with the tools `bank-trust-statement.mjs` and `bank-execution-check.mjs`. It is specified in [bank credential trust v1](../protocol/bank-credential-trust-v1.md). Responsibility moves to the bank: keep the trust key, registry, pinned keys and heads outside Auth Core, and run the check before every execution.

## D-042 The SDK reports the signing key fingerprint computed on the device (phase 12)

Without a key fingerprint from the device, the bank could only approve the key Auth Core reports, which a compromised Auth Core chooses. `signingKeyFingerprint()` (Android and iOS) returns the SHA-256 of the active signing key's SubjectPublicKeyInfo, read from the Keystore or Secure Enclave. The change is additive: no change to the wire protocol, the registration response or the stored keys. Vectors are in `bank-trust-v1.json`; the Android JVM test runs against them. The iOS code and test are not compiled here.

## D-043 Two races in the Android call controller (phase 12)

The intermittent SDK call conformance failure of phase 11 had two causes, both in `VerificationCallController`:

1. `end()` published `Ended` before releasing the media engine.
2. The answer handler checked `WaitingForOperator` and then wrote `Connecting`. A `CONNECTED` event handled on another thread could land in between, so the state went back from `Connected` to `Connecting`. Confirmed by a trace.

Fixes: the controller now releases first and publishes `Ended` last, with an internal `ending` flag, and the move to `Connecting` is a `compareAndSet`. Results: conformance 19/25 runs passed before, 50/50 after. The iOS controller is an actor and was not changed; nothing was run there.

## D-044 One execution boundary on the bank's side; the adapter needs its permit (phase 13)

The phase 12 decision protected only where a bank chose to call it; a CLI is not an integration. This repository has no bank backend and no payment adapter: `demo/bank-backend` executes nothing, Auth Core only records commit states, the sandbox is a self-contained simulator. So the integration is delivered as a contract plus a reference implementation (`bank-integration/`), not as a claim that a bank is integrated.

`execute(paymentId)` is the only function that may reach the payment system. The adapter is wrapped so that it executes only an order for which the boundary issued a one-time permit. Errors before the adapter hold the payment; errors in the adapter leave the outcome unknown, and the next attempt reconciles by lookup instead of executing again. Auth Core's commit request is a precondition; `confirmed` is not read.

## D-045 Atomic where the bank's database can make it so; reconciliation where it cannot (phase 13)

Claim, final check with the move to `EXECUTING`, revocation, and `EXECUTED` with the head are single PostgreSQL transactions. The credential's trust row is read `FOR SHARE` by the final check and locked `FOR UPDATE` by a revocation, so the two are ordered. The bank's database and the payment system cannot share a transaction. The contract therefore requires an idempotency key the payment system honours and `lookup` by that key; it marks `OUTCOME_UNKNOWN` and `REVIEW`, and `revoke()` reports payments already past their final check. No cross-system atomicity is claimed.

## D-046 Authority to send a payment lives in the bank's database, not in memory (phase 14)

The phase 13 one-time permit lived in the boundary's memory. A second instance issued its own permits, and any module holding the raw adapter called it directly (reproduced on `603dae9`). The payment gateway now runs as a separate component with its own PostgreSQL role. That role can only call `bank_submit`, `bank_resubmit` and `bank_operation_for_lookup`. They are `SECURITY DEFINER` functions that send the order stored with the payment, only for the attempt holding the `APPROVED` row, once. The boundary's role cannot set `SUBMITTED`: the trigger allows it only for the schema owner, under which the functions run. Callers of the gateway are authenticated with mutual TLS and an allow-list of certificate names. These are standard mechanisms (least privilege, server-side checks, mTLS); no custom cryptographic protocol is used. Bearer tokens and in-memory objects are not used as proof of authority.

## D-047 The bank's decision, the command and the provider's confirmation are separate states (phase 14)

`EXECUTING` is split:

- `APPROVED`: the bank's decision; the revocation cut-off;
- `SUBMITTED`: written by the gateway before it calls the provider;
- the provider's answer: `EXECUTED`, `PROVIDER_FAILED` or `PENDING_PROVIDER`.

No answer leads to `OUTCOME_UNKNOWN`, then `RECONCILING` by lookup. The database enforces the transition table for every role. Auth Core's `COMMITTED` is only the bank's report after `EXECUTED`.

## D-048 Exactly-once execution is a property of the provider's contract (phase 14)

The bank declares what its provider guarantees (`providerCapabilities: { idempotentSubmit, lookup }`, both false by default). Behaviour by contract:

- **without lookup:** an unknown outcome goes to `REVIEW`;
- **without idempotent submission:** a `not_found` goes to `REVIEW`;
- **with both:** a `not_found` is resent with the same operation ID.

A payment is never resent only because no answer came. The gate for exactly-once execution with a real provider stays BLOCKED until a provider contract is provided and tested.
