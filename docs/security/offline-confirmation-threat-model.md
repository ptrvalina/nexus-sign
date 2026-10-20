# Offline confirmation: threat model (FI-004)

Status (2026-10-18, phase 8): **offline confirmation v2 (deferred device signature) implemented in Auth Core and the Android SDK, written for the iOS SDK; gate G2 stays PARTIAL** until the SDKs are built and run on devices and the residual cases below are accepted. Protocol: [offline confirmation v2](../protocol/offline-confirmation-v2-deferred-signature.md), decision: [ADR 0018](../adr/0018-deferred-device-signature.md). Tests: `auth-core/test/integration/offline-deferred-signature.test.mjs` (v2), `offline-forgery.test.mjs` and `offline-limits.test.mjs` (v1), `master-key-hsm.test.mjs`.

## The path of an offline confirmation

| Step | Where | What is checked or stored | Secret involved |
|---|---|---|---|
| 1. Enrolment | device, Auth Core | Device sends signing, authentication and offline public keys; Auth Core derives `K = HKDF(ECDH(Z), "NEXUS-SIGN/OFFLINE/v1", credentialId)`, stores `K` under the device master key (`credentials.offline_secret_encrypted`, AES-256-GCM, AD `device:<credentialId>`), returns its public key, discards its private key; the keys are sealed in a `CREDENTIAL_ENROLLED` evidence record | device private keys (phone hardware), `K` (both sides), device master key (Auth Core) |
| 2. Operation | bank → Auth Core | `POST /v1/authorizations`: terms validated (display rules), canonicalized, hashed; row immutable by trigger (terms, policy reference and version since migration 022) | — |
| 3. Challenge | bank screen | `GET …/offline-challenge`: only `PENDING_USER`, not expired, credential offline-enabled, within the amount cap; QR `NXS2.` (v2) or `NXS1.` (v1) + canonical bytes | — |
| 4. Device | phone, no network | Strict parse of the bytes, own `credential_id`, expiry by the phone's clock; terms shown from the bytes; local user authentication; **v2: ECDSA signature with the signing key, stored**; then the code `trunc8(HMAC(K, domain ‖ SHA-256(bytes)))` | signing key, offline key / `K` |
| 5. Code submission | customer → bank screen → bank backend → Auth Core | `POST …/offline-confirmation` (bank client credentials, certificate binding) | — |
| 6. Code check | Auth Core | Under row lock: state, expiry, identity and credential `ACTIVE`, enrolment integrity, plan, amount cap, daily ceiling, constant-time compare with the code recomputed from `K`; five failures reject | `K`, device master key |
| 7. Result | Auth Core | v1: `VERIFIED`, evidence `OFFLINE_CODE` (HMAC tag). **v2: `OFFLINE_PROVISIONAL`**, or `VERIFIED` if the device signature is already stored | HSM evidence key (v1) |
| 8. Signature upload (v2) | phone → Auth Core | Device-signed request from the bound credential; signature verified with the enrolment-sealed key over the stored bytes; one per authorization; `OFFLINE_PROVISIONAL` → `VERIFIED` (`OFFLINE_SIGNED`), evidence sealed | device authentication key, HSM evidence key |
| 9. Missing signature (v2) | Auth Core sweep | Deadline passed or credential/identity not `ACTIVE` → `OFFLINE_UNSIGNED`, audit and webhook | — |
| 10. To the bank | webhooks (outbox), `GET /v1/authorizations/{id}`, evidence export | `authorization.offline_provisional`, `.verified`, `.offline_unsigned`, `evidence.appended` with HSM-sealed chain heads | webhook secret |
| 11. Execution | **bank** | The bank decides whether and when to execute; Auth Core's `bank-commit-request` needs `VERIFIED` | — |

## Who can get an offline confirmation accepted — before and after v2

"Accepted" means: Auth Core reports `VERIFIED` and seals evidence. In v2 a code alone yields only `OFFLINE_PROVISIONAL`, which Auth Core never reports as a confirmation.

| Compromise | Preconditions | v1 (code only) | v2 (deferred signature) | Still possible in v2 | Existing measures / evidence |
|---|---|---|---|---|---|
| Network observer, bank screen observer | sees the QR and the typed code | no: code bound to one authorization, single use, 5 attempts | no | nothing beyond v1 | `offline-forgery` 1, 2, 4 |
| Another customer or device | own credential | no: different `K` | no: different `K` and signing key | — | v1 test 2; v2 test 4 |
| Bank backend | bank client credentials | no (guesses only) | no | creates payments, chooses what to show on its own screen (the phone shows the signed bytes), may execute on `PROVISIONAL` at its own risk | v1 tests 1, 2 |
| **Database only** (read/write as the application role) | DB access, no master key | no: `K` encrypted, terms immutable | no: additionally, a signature row it inserts is re-verified, the table is append-only | flip `state` to `VERIFIED` with junk in `signature` (the trigger permits a transition with a signature value) — **no evidence record is produced**, so a bank that relies on sealed evidence is not misled; deny service | v2 tests 14, 15; state-machine property test |
| Database + configuration, `MASTER_KEY_SOURCE=env` | DB copy, device master key | **yes**: decrypt `K`, compute codes (submitted via the bank API or a controlled Auth Core) | **only `OFFLINE_PROVISIONAL`**, ending in `OFFLINE_UNSIGNED` | a provisional result the bank might act on if it ignores the state | v1 test 6; v2 test 16 |
| Database + configuration, `MASTER_KEY_SOURCE=hsm`, no HSM reach | DB copy, wrapped keys | no: master key wrapped by the HSM KEK | no | — | `master-key-hsm` test 2 |
| Database + configuration + HSM reach (PIN) | as above plus network path to the HSM | **yes** | only `OFFLINE_PROVISIONAL` | as the row above | KEY_MANAGEMENT.md |
| **Running Auth Core process** (code execution) | control of the process | **yes**: holds the master key and `K`, computes and accepts codes, seals evidence | cannot produce the device signature, so cannot produce an `OFFLINE_SIGNED` record that verifies | (a) seal a **forged `OFFLINE_CODE` (v1-style) record** with the HSM evidence key — a bank verifier with `--reject-offline-code` refuses it; (b) seal a record with an invalid ECDSA signature — any verifier refuses it; (c) seal a fake `CREDENTIAL_ENROLLED` record for an attacker key and then a validly signed `OFFLINE_SIGNED`/`DEVICE_SIGNATURE` record — detectable only if the bank reconciles enrolments (`evidence.appended` for an enrolment it never initiated); (d) mark authorizations `VERIFIED` without evidence; (e) withhold, delay or refuse signatures and webhooks; (f) serve a different QR to the bank screen — the phone shows those terms, so this depends on the customer reading them | ADR 0009, FI-019 heads |
| Admin console account | operator or admin login (TOTP) | no direct path | no direct path | revoke a credential (provisional confirmations then end `OFFLINE_UNSIGNED`): denial of service; operator decisions for AUDIO/VIDEO channels affect the plan, not the signature | route review; four-eyes revoke (ADR 0014) |
| **Customer's phone compromised** | malware with key use (biometric bypass) | yes | yes: the device key is the trust anchor | sign any authorization the phone receives | attestation at enrolment only (FI-007, open) |
| Stolen phone, no biometrics | possession | no | no | — | biometric-bound keys |

## What changed with v2, precisely

- The trust anchor of an offline confirmation moves from `K` (shared with Auth Core) to the device signing key (only on the phone), the same as online.
- Auth Core's own capability to *confirm* offline payments is removed; its capability to *deny*, *delay* and *mislabel* remains, and so does its capability to forge evidence records of a kind a verifier accepts unless told otherwise (v1 `OFFLINE_CODE`), and to forge enrolments.
- Detection replaces silent acceptance for the insider cases: a code accepted without a following signature becomes `OFFLINE_UNSIGNED` (audit `offline_signature_missing`, webhook `authorization.offline_unsigned`). A genuine signature arriving after the deadline is recorded (`deferred_signature_late`, `verified: true`) for investigation.

## What the device can and cannot establish offline

- It **can** check that the bytes are well formed, name its own credential, and have not expired *by its own clock*; display them; authenticate the user locally; sign them.
- It **cannot** know whether the authorization still exists, was cancelled, was already confirmed (online or on another channel), whether its credential was revoked, or the true time. Auth Core enforces these at upload; until then nothing is confirmed.
- So the signature proves that the enrolled phone approved those exact terms after local user authentication; it does not prove when, that the customer understood them, or that the payment should be executed. **The bank remains the source of truth** for the account, limits, risk and execution.

## Residual risks after v2 (not hidden by limits)

1. **Provisional acted upon.** A bank that executes on `PROVISIONAL` (to keep the branch experience fast) carries the v1 risk for those payments. Auth Core cannot prevent it; it labels the state and refuses its own commit flow. The amount cap and daily ceiling still bound the exposure in that case; they are bounds, not a fix.
2. **Forged v1 records by a controlled Auth Core.** Closed only if the bank's verifier runs with `--reject-offline-code` from the v2 switch date on.
3. **Forged enrolment by a controlled Auth Core.** Requires the bank to reconcile `CREDENTIAL_ENROLLED` heads against its own enrolment and replacement actions (FI-019 delivers the heads; the reconciliation is bank-side and not implemented here).
4. **Compromised phone.** Out of reach of any protocol change; per-operation integrity attestation (FI-007) is open.
5. **Old SDKs.** On a v2 deployment they refuse `NXS2.` QR codes; customers on old app versions cannot confirm offline until the bank ships the SDK.
6. **Rollback of Auth Core's database** after an upload produces a false `OFFLINE_UNSIGNED` (the phone already deleted the signature); never a false `VERIFIED`.
7. **Android UX.** Two biometric prompts (one per key). iOS is designed for one evaluation; not verified on a device.
8. **Unverified platforms.** The iOS implementation is not compiled here; the Android SDK is compiled for the JVM against stubs only.

## Bounds that remain in force

Amount cap per currency (`OFFLINE_CONFIRMATION_MAX_AMOUNT`) and per-credential daily ceiling (`OFFLINE_CONFIRMATION_MAX_PER_CREDENTIAL_PER_DAY`, counting accepted codes, provisional or not, checked under a per-credential lock in the accepting transaction), both required in production; `OFFLINE_CONFIRMATION_MODE=deferred_signature` required in production.

## Not chosen

- Computing the HMAC inside the HSM: keeps `K` out of process memory but the process can still ask the HSM for a code; it does not move the boundary for an attacker controlling Auth Core.
- Longer codes: raise guessing cost but do not affect the insider case.
- Letting a deferred signature alone confirm a `PENDING_USER` authorization: cryptographically equivalent to an online confirmation, but it would make the deferred endpoint a second online path with different expiry rules; v2 requires both the code and the signature.
- A second signed format with its own domain: the existing canonical bytes already bind every field the decision depends on, including the purpose (`domain`).

## Phase 9: scenario verification against the code

Each row names the test that exercises it on the current code (`offline-deferred-signature.test.mjs` = DS, `offline-enforcement.test.mjs` = EN). "Prevented" means Auth Core refuses; "detected" means it is visible to the bank or an auditor but not stopped.

| Scenario | Attacker gets | Still possible | Prevented | Only detected | Trusted components still needed | Test |
|---|---|---|---|---|---|---|
| Database write access (application role) | rows | set `state = 'VERIFIED'` with junk in `signature`; insert rows into `evidence_records` and `offline_deferred_signatures`; deny service | **commit** of such a row (evidence re-verified: seal, binding, device signature); finalization with an inserted signature row; changing terms, policy, offline fields | the false `VERIFIED` is visible in `GET` until the bank checks evidence; `integrity_violation` audited on the commit attempt | HSM evidence key, enrolment records, Auth Core process | EN 3, 4; DS 14, 15 |
| Database + device master key (`env`) | `K` | compute codes → `OFFLINE_PROVISIONAL` | `VERIFIED`, commit | `OFFLINE_UNSIGNED` after the deadline | device signing key on the phone | DS 16 |
| Knowledge of `K` alone | codes | as above | as above | as above | — | DS 16 |
| Running Auth Core (code execution, HSM session) | everything the process can do | delay or block uploads and webhooks; refuse service; serve a different QR to the bank screen (the phone shows those terms); seal a v1-style `OFFLINE_CODE` record; seal a fake `CREDENTIAL_ENROLLED` and then a validly signed record with an attacker key; mark rows `VERIFIED`; answer the bank's commit request as it likes | nothing inside Auth Core can be relied on | v1 record: a v2 deployment's commit check and `verify-evidence --reject-offline-code` refuse it; invalid ECDSA: any verifier; fake enrolment: only by the bank reconciling `evidence.appended` enrolments with its own enrolment actions | bank-side verifier with keys obtained out of band, bank reconciliation | EN 6 (v1 record), DS 13, 20 |
| Forged evidence record (copied, re-pointed, altered) | a row | — | commit (names another authorization; hash/seal mismatch) | verifier fails it | HSM evidence public keys | EN 4, DS 13 |
| Forged device registration (database only) | a row | — | use of the key (credential integrity against the sealed enrolment) | `integrity_violation` | sealed enrolment | `evidence-integrity` (key replaced in the database cannot approve; verifier rejects a key that differs from the sealed enrolment) |
| Signature by another enrolled device | its own key | — | upload (403 / 422); service-level check without HTTP | audit `deferred_signature_invalid` | — | DS 4, EN 1 |
| Replacement device signs for the replaced one | new credential | — | upload (403); replaced device cannot authenticate (401); sweep ends the authorization `OFFLINE_UNSIGNED` | webhook `authorization.offline_unsigned` | — | EN 5 |
| Device revoked before the upload | — | — | upload; commit | `OFFLINE_UNSIGNED` (`credential_not_active`) | — | DS 5 |
| Signature reuse (repeat, other authorization, after deadline) | a valid signature | — | second transition (`ALREADY_RECORDED`, one evidence record); use for another authorization (422); late use (409) | `deferred_signature_late` with `verified: true` | — | DS 1, 3, 8, 8b, 10 |
| Alternative endpoint or webhook | API access | — | device `/signature`, bank `/signature`, second code, escalation: all refuse an `OFFLINE_PROVISIONAL` authorization; Auth Core has no inbound webhook that changes state | — | — | EN 2 |
| Old SDK | code only | — | `NXS2.` refused by the SDK parser; a code alone is never `VERIFIED` | — | — | Android `OfflineSignatureQueueTest`; DS 1 |
| Configuration change | config access | set `immediate` outside production with `ALLOW_INSECURE_DEVELOPMENT=true` | `immediate` in production (startup refused); `immediate` outside production without the insecure flag (startup refused) | startup warning lists `OFFLINE_CONFIRMATION_MODE=immediate` | deployment review | DS 18, EN 7, unit posture test |

## Phase 10: compromise scenarios re-assessed against the code (2026-10-18)

Changes since phase 9 that matter here: the commit check also requires the record's chain position and link; `confirmed` in the bank's `GET` is derived from evidence that verifies now, not from the state column; the device parsers check ID and nonce formats. Tests: `evidence-forgery-hsm.test.mjs` (FH, records with a genuine SoftHSM seal), EN, DS.

| Scenario | The attacker can | Auth Core prevents | Detected afterwards | Still possible |
|---|---|---|---|---|
| Database access only | write rows (state, evidence, signature rows), read ciphertexts | commit of a `VERIFIED` row without valid evidence; finalization with an inserted signature; changes to terms, policy, offline fields; reading `K` | `confirmed: false` + `evidenceProblem` in `GET`; `integrity_violation` on a commit attempt; the bank's retained chain heads (`--heads`) | deny service; make `GET` show `state: VERIFIED` (with `confirmed: false`) |
| Database + master keys | compute offline codes | `VERIFIED` and commit without the device signature | `OFFLINE_UNSIGNED` | provisional states the bank must not act on |
| Access to a running Auth Core (API calls as a bank or device it impersonates, no code execution) | what the API allows that identity | everything above | audit log | — |
| Full control of Auth Core (code execution, HSM session) | everything the process can: seal records with the real evidence key (FH shows the commit check and the verifier still refuse wrong signatures, other keys, wrong positions), seal a fake enrolment plus records signed by its key, answer commits as it likes, block or delay | nothing; the checks run in the same process | only outside Auth Core: the bank's verifier with keys obtained out of band, `--reject-offline-code`, `--heads`, reconciliation of `CREDENTIAL_ENROLLED` heads with the bank's own enrolment actions (not implemented) | forged enrolments followed by validly signed approvals; denial of service |
| Customer device compromised (key use) | sign any authorization the phone receives | — | — | everything the device key authorizes (FI-007) |
| Registered operator abusing the console | mark an AUDIO/VIDEO channel VERIFIED or FAILED for calls they claimed; revoke devices (four-eyes) | confirming a payment: the operator decision only satisfies a plan step, the device signature is still required | audit of claim and decision; evidence `verificationFactors` names the operator | pass a customer through a call the operator did not conduct honestly |
| Device registration compromised (fake enrolment) | via database only: replace keys in a row | use of a key that differs from the sealed enrolment (credential integrity) | `integrity_violation` | via a controlled Auth Core: see that row |
| Repeated execution | resend commit requests, reuse evidence | a second commit with another reference (409); one `COMMIT_REQUESTED` per authorization under the row lock (FH: 20 parallel same reference → one recorded request; 10 different → one accepted) | — | the bank executing twice on its side if it ignores the commit result (bank's idempotency on `bankTransactionReference`) |
| HSM failure | — | start with an unavailable HSM; sealing without the HSM (confirmation fails, nothing committed) | logs, readiness | outage of confirmations |
| HSM compromise (key use) | seal arbitrary records | records whose device signature, binding, enrolment link or chain position is wrong (FH) | verifier | records consistent in every respect for a key also enrolled through the compromise (with a controlled Auth Core) |
| Data substitution before signing | change what the bank screen or the API shows | anything the device does not display: the device signs only bytes it parsed strictly and displayed; formats are checked (phase 10) | the evidence carries the signed bytes | look-alike payee names are signed as they are (vector added; FI-034 open); the customer may not read the screen |
| Delivery channel compromise (network, push, QR) | observe, delay, replay, drop | replay of device requests (nonces), replay of codes (single use), signatures for other authorizations | — | delay and drop: provisional confirmations end `OFFLINE_UNSIGNED` |

Who executes: Auth Core never moves money. The bank's system executes, and the only point where Auth Core can stop it is `bank-commit-request`: the evidence check and the `PENDING → COMMIT_REQUESTED` transition happen in one transaction under the authorization's row lock, so there is no window between check and state change inside Auth Core. Between Auth Core's 202 and the bank's own execution the bank is responsible: execute once per `bankTransactionReference`, only after the 202, and report the result.

## Phase 11: evidence row metadata and trust boundaries (2026-10-19)

**What prevents substituting record metadata.** The application role cannot change evidence (`UPDATE` revoked, append-only trigger on `UPDATE`, `DELETE`, `TRUNCATE`); a copied record collides with `UNIQUE (authorization_id)`, `(nexus_id, chain_sequence)` and `(nexus_id, previous_evidence_hash)`. A table owner who disables the trigger can still change columns. Since phase 11 every column that repeats a sealed value must equal it at the commit, in `confirmed`, in the enrolment check and in the verifier (D-038, D-039); the seal itself proves the payload. Tests: `evidence-metadata-binding.test.mjs` (MB) 1–11 with genuine SoftHSM seals.

**What prevents substituting the registered public key.** The key used to verify a device signature must equal the key sealed in the credential's `CREDENTIAL_ENROLLED` record, whose seal, payload and columns are checked on every use. A database writer who replaces `public_key_pem` gets `credential_integrity`; one who also changes the enrolment row breaks its seal or its column binding.

**A compromised Auth Core can register an attacker key.** The enrolment record is sealed by Auth Core with the evidence key it holds; a party controlling the running process (or the HSM session) can seal an enrolment for any key and then confirmations signed by it, consistent in every respect the checks and the verifier look at. Nothing in this phase changes that.

**What the bank must reconcile on its own side.** The credential IDs it accepted for each customer in step 5 of the bank guide (from its own records, not from Auth Core) against the `credentialId` and enrolment record of every confirmation it executes; the chain heads from `evidence.appended` (`--expect-head`); evidence exported and verified with keys obtained out of band, not from the export. An enrolment the bank did not initiate or accept is an incident.

**Needs a separate architectural phase.** Enrolment approved outside Auth Core (the bank countersigning the device key, or verifying the device attestation itself), evidence keys and chain heads anchored outside Auth Core's control, and an independent check of attestation chains in the verifier.

| Scenario | Prevented | Detected | Still possible | Test |
|---|---|---|---|---|
| `nexus_id`, `credential_id` or both changed in an `AUTHORIZATION` row | commit (409 `EVIDENCE_INVALID`), `confirmed: true` | `integrity_violation`; verifier `record metadata does not match the sealed payload`; gap in the owner's chain | deny service on that authorization | MB 2–4, 7 |
| `authorization_id` moved to another authorization | commit of the target | binding check; verifier | — | MB 5; FH re-pointed |
| `record_type`, `chain_sequence`, `seal_key_id`, `schema_version` changed | commit | verifier | — | MB 6 |
| Enrolment row columns changed | use of the credential (new confirmations, commit) | `integrity_violation` | — | MB 8, 9 |
| Many parallel requests on a refused record | every request refused with 409, no `COMMIT_REQUESTED`, one security event each | — | — | MB 10, 10b |
| Revocation overlapping a commit request | a request decided after the revocation committed | — | a request that overlaps an uncommitted revocation is ordered before it | MB 11 |
| Record moved out of the newest position of its chain | — | only with a chain head the bank kept | without kept heads: invisible in the chain | MB 2 note; `evidence-checkpoints` |

## Phase 12: a fully compromised Auth Core, the bank in control of its own systems (2026-10-19)

Model: the attacker controls Auth Core completely (its code, its database as owner, its HSM session). The bank's backend, its record of devices, its trust key, its pinned evidence keys, its kept chain heads and the customer's device and bank app stay under the bank's and the customer's control.

| Can a compromised Auth Core on its own … | Result | Evidence |
|---|---|---|
| 1. register a new credential (no bank token, invented replacement authorization, attestation claimed verified) | **yes** | `bank-trust-compromise.test.mjs` 2, 10 (Auth Core's compiled `createCredential` on SoftHSM) |
| 2. seal its enrolment with a valid HSM seal | **yes**: the real evidence key | 2, 3 |
| 3. have the attacker sign a confirmation with the new key | **yes** | 2, 3 |
| 4. get `VERIFIED`, `confirmed: true` and a 202 for the commit request | **yes** | 2, 3 (`authCoreSaysYes`) |
| 5. produce an export the independent verifier accepts with the pinned evidence keys | **yes** | 2, 3 |
| … get the bank to execute | **no**, if the bank runs its own check ([bank credential trust v1](../protocol/bank-credential-trust-v1.md)): the key is not one the bank approved with its own trust key | 2–11; 12 mutations of the check, all caught |

Distinct properties, not interchangeable:

| Property | Established by |
|---|---|
| Cryptographic validity of the device signature | anyone (verifier) |
| Integrity of the evidence | anyone with the pinned evidence keys |
| Genuineness of the device registration | the bank: the fingerprint reported by its app through its own channel matches the sealed key |
| The bank's permission to trust the device | the bank: an approval signed with its trust key, not revoked |
| Permission to execute this transaction | the bank: the decision, including the terms it asked for |

Keys and where they live:

| Key or data | Holder | May be taken from Auth Core? |
|---|---|---|
| Evidence sealing key | HSM used by Auth Core | — (it signs; a compromised Auth Core can use it) |
| Evidence public keys and their rotation history | the bank, recorded at the key ceremony and at each rotation, out of band | **no**: the keys in an export are Auth Core's claim |
| Bank trust key (statement signing) | the bank's HSM | never given to Auth Core |
| Approvals, revocations | the bank's registry | no |
| Chain heads | the bank, from every `evidence.appended` | received from Auth Core once, kept by the bank, then compared |
| Device signing key fingerprint | the customer's device (SDK), via the bank's app | no |

Detection: an unapproved registration, an unknown, revoked or substituted key, an evidence key the bank did not pin, a changed kept head, and a chain cut before a kept head are all detected. Records removed **after the last head the bank kept** are not detectable, and the guide does not claim otherwise.

Residual risks:

- denial of service by Auth Core;
- a compromised bank backend or bank app;
- attestation provenance checked only by Auth Core;
- the customer's own compromised device (FI-007).

Each needs a separate architectural decision. Auth Core itself does not enforce bank approvals: under the stated model such a check would run inside the compromised component. It is therefore not part of this protocol.

## Phase 13: where the bank's decision is enforced (2026-10-19)

The phase 12 decision protects only where every path to execution goes through it. Phase 13 adds the execution boundary (`bank-integration/`, [trust boundary](../architecture/bank-trust-boundary.md)): the only code that may call the payment adapter, through a one-time permit. `bank-execution-boundary.test.mjs` (EB, numbered in file order; Auth Core on SoftHSM, the bank's store in PostgreSQL) checks in every negative case that the adapter was not called.

| Attack or failure | Result | Test |
|---|---|---|
| VERIFIED, `confirmed: true`, 202 for a key the bank never approved | refused, adapter not called, `CANCELLED` reported | EB 2 |
| key substituted, revoked, approved for another customer | refused | EB 3–5 |
| amount, beneficiary, currency, reference or operation type changed | refused | EB 6 |
| evidence or a whole chain re-sealed with a key shipped in the export | refused (pinned keys) | EB 7, 22 |
| damaged evidence, broken chain, changed or withheld kept head, a statement written around the registry | refused | EB 8, 9, 20, 21, 23 |
| registry, Auth Core unavailable or too slow | held, executed once it is back | EB 10 |
| 20 parallel requests through two instances; a live claim; an expired lease taken over | one execution | EB 11, 18, 19 |
| replayed evidence of another authorization; one authorization for two payments | refused; refused by the store | EB 12 |
| adapter called without, with a reused, or with another order's permit | `BoundaryBypassError`, adapter not reached | EB 13 |
| revocation while the payment is checked, between the decision and the final check, after the final check | refused, refused, reported as in flight | EB 14, 17, 15 |
| timeout after the payment system executed; payment lost | reconciled by lookup, one execution; `REVIEW` | EB 16 |

Still not addressed:

- **Denial of service.** Auth Core can refuse or delay; the boundary then holds or refuses, never executes.
- **A compromised bank backend or bank app.** It can call the adapter directly, change the registry or report a false fingerprint. The permit guards one process only.
- **Device attestation.** Checked by Auth Core only.
- **Integration.** The boundary is not integrated into a real bank backend or payment system.

## Phase 14: several processes, crashes and unknown outcomes (2026-10-19)

The gateway runs in its own process with its own database role, behind mutual TLS ([payment state machine](../architecture/payment-state-machine.md), [pilot execution pack](../integration/pilot-execution-pack.md)). Tests: `bank-execution-processes.test.mjs` (EP), with the gateway as a separate process, a provider double behind HTTP and barriers at each step.

| Attempt | Result | Test |
|---|---|---|
| A second instance, or a module, issues its own permit (phase 13 design) | reproduced on `603dae9`; removed | reproduction log |
| Gateway called without a certificate, with another CA's, or with another service's certificate | TLS refusal; 403 | EP «callers» |
| Gateway called for a payment not approved, still `CHECKING`, for another attempt, or a second time | refused, nothing sent | EP «approval is for one attempt», «still checking» |
| Request carrying a changed amount or beneficiary | the stored order is sent | EP «approval is for one attempt» |
| Terms changed in the database after approval (owner, trigger disabled) | `REVIEW`, nothing sent (hash bound at approval) | EP «terms changed» |
| Boundary role sets `SUBMITTED`; gateway role reads or writes tables | refused by the database | EP, EB «around the boundary» |
| Forbidden transitions, deletes, changed terms, head moved back | refused by the database | EP «forbidden transitions», «chain head» |
| Revocation before or at the approval; after it | refused; executed and reported as in flight (the cut-off is `APPROVED`) | EP «revocation at each step» |
| Crash at each transition | the next attempt finishes; one transfer | EP «a crash at each transition» |
| Gateway process killed after the provider executed | unknown; reconciled after restart; one transfer | EP «gateway killed» |
| Pending, failed, nonsense, lost, late answers | `PENDING_PROVIDER`, `PROVIDER_FAILED`, then reconciled; one transfer | EP «provider answers» |
| Provider not idempotent; no lookup in the contract | never resent; `REVIEW` | EP «not idempotent», «no answer and not found» |
| Local state and provider disagree | finding recorded, state unchanged | EP «disagree» |
| Repeated or forged webhooks; a correctly signed webhook for an unapproved key | one execution; 401; refused | EP «webhooks» |
| Device replaced during the check | refused at the approval | EP «device replaced» |
| Compromised Auth Core's answers with keys, a registry, heads | ignored; errors refuse | EP «compromised Auth Core» |

Not covered:

- a compromised bank backend: the boundary's role and certificate;
- the schema owner's credentials;
- a compromised provider;
- exactly-once execution with a real provider (its contract: BLOCKED);
- denial of service.

## Phase 15: the bank's database roles (2026-10-20)

Phase 14 left the boundary's database role with `INSERT` and `UPDATE` on the journal, the log and the registry; reproduced on `3cbea86` ([bank database authorization](bank-database-authorization.md), section 1). Since phase 15 no application role writes a table; every change is a `SECURITY DEFINER` function of the owner, and the gateway checks the approval again. Tests: `bank-db-authorization.test.mjs` (DA), with EP and EB.

| Attempt | Result | Test |
|---|---|---|
| Boundary role: `UPDATE … SET state = 'APPROVED'`, change `credential_id` or `order_hash`, insert an execution, delete it | permission denied; state unchanged; gateway refuses; provider not called | DA 1 |
| Boundary role: write the registry, a trust statement, the terms | permission denied | DA 1 |
| Any role: insert, change or delete log rows; owner: change, delete or truncate them | permission denied; append-only | DA 2, EP «forbidden transitions» |
| The log after a real execution | one row per transition, with the function and the login role that made it | DA 2, EP «state machine» |
| Owner's own SQL: `CHECKING → APPROVED` without `bank.approve`; riding on a function's announcement; changing an approved order with a hand-set announcement | not a permitted transition; immutable | DA 3 |
| Gateway role calling its functions directly, without the gateway's check: not approved, other attempt, changed reference, twice, outcome for another attempt or after a final state | refused | DA 4 |
| `bank.approve` with an expired lease, a revoked credential, another customer's, an unknown one, an old attempt, a second time, an unbounded lease, evidence for other terms, another authorization, another customer, none | refused, state `CHECKING` | DA 5 |
| A forged confirmation approved through the boundary (right shape, wrong device key); a statement stored without the bank's signature | approved by the database (it cannot verify ECDSA); `REVIEW` at the gateway; nothing sent | DA 6 |
| Terms or reference changed after the approval (owner, trigger disabled) | `REVIEW` at the gateway; nothing sent | DA 7, EP «terms changed» |
| Revocation during an approval, approval during a revocation | serialized on the trust row; refused, or reported in flight and sent (cut-off at `APPROVED`) | DA 8 |
| Approval rolled back; connection lost inside the transaction | nothing left; the sanctioned path works afterwards | DA 9 |
| Boundary recording `EXECUTED` or submitting; gateway approving, reading tables, changing the registry; registry or operator approving | permission denied | DA 10, EB «around the boundary» |
| A review resolved under another name | the database records the login | DA 11, EP «no answer» |
| A role inheriting the boundary role; `SET ROLE` to the owner or the gateway | the boundary's functions only; refused | DA 12 |
| Objects put in the functions' way: in `bank`, in `public`, temporary tables, a function named like a built-in | permission denied; definer functions have `search_path = pg_catalog, pg_temp`; none executable by `PUBLIC` | DA 13 |
| Extra grants from an earlier version, a `PUBLIC` grant, phase 14 tables in `public`, objects created later; a superuser or a member of the owner given as a service role | removed on reinstall; not granted; refused | DA 14 |

Not covered:

- the schema owner and the PostgreSQL superuser: they can change or disable any of this (R-26; operational controls in [bank database authorization](bank-database-authorization.md), section 7);
- a compromised boundary *and* a genuine customer confirmation: it can cause that confirmed payment, with its terms, as before;
- a compromised gateway: it holds the provider's credentials;
- a shared database login for several operators or components: the log then cannot attribute;
- PostgreSQL versions other than 16.13.
