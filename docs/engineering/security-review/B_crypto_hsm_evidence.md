# B — Cryptography, HSM and Evidence Audit (NEXUS-SIGN 2.0.0-rc.2)

Auditor scope: auth-core crypto, HSM adapters, master keys, evidence chain, independent verifier.
Repository: `nexus-sign` @ `5999984` (read-only; nothing modified). Scratch scripts: `audit/tmp_B/`.

## 1. Scope actually read

- `src/crypto/`: hsmAdapter.ts, selectHsmAdapter.ts, softwareHsmAdapter.ts, pkcs11HsmAdapter.ts (full), masterKeyVault.ts (full), secretBox.ts (full), ecdsaSignatureFormat.ts, der.ts, p256PublicKey.ts, jws.ts, password.ts, totp.ts, tokenDigest.ts, appleRootCert.ts. (androidAttestationRoots.ts: not read beyond listing.)
- `src/services/`: evidenceService.ts, credentialIntegrity.ts, authorizationEvidenceCheck.ts (full); authorizationConfirmation.ts lines 95–260 and 455–649 (call sites, atomicity); canonicalAuthorization.ts (normalize/canonicalJson); adminAuthService.ts (TOTP/password call sites, grep).
- `src/config/env.ts`, `src/config/productionPosture.ts`, `src/server.ts`, `src/routes/nexusV1.ts` (evidence export routes).
- `src/cli/`: masterKeys.ts, rotateSecretKeys.ts, sealCredentialBaseline.ts.
- `scripts/`: verify-evidence.mjs, lib/evidence.mjs, lib/bankTrust.mjs, bank-trust-statement.mjs, verify-baseline.sh, db/roles.sql, run-local.sh (env section).
- Migrations 009, 013, 020; `src/db/schema.sql` evidence/audit section; `.env.example`; `docker-compose.yml`; `Dockerfile` (grep).
- Tests (read headers/test names, partially bodies): test/crypto, secret-box, evidence; integration/hsm, master-key-hsm, evidence-*, key-rotation*, support/softhsm.mjs, support/syntheticEvidence.mjs.
- Docs: docs/security/hsm-key-management.md, docs/engineering/KEY_MANAGEMENT.md (grep + key sections), runbooks/key-rotation.md (evidence part), runbooks/hsm-unavailable.md (adapter behaviour), docs/protocol/evidence-format.md (grep), ADR 0004. Not read in full: bank-credential-trust-v1.md, evidence-verification-failure.md, ADR 0009.

## 2. Commands run and output

```
$ node --test test/crypto.test.mjs            # pass 7  fail 0
$ node --test test/secret-box.test.mjs        # pass 3  fail 0
$ node --test test/bank-trust.test.mjs        # pass 3  fail 0
$ node --test test/protocol.test.mjs          # pass 2  fail 0
$ node --test test/admin-totp.test.mjs        # pass 3  fail 0
$ node --test test/production-posture.test.mjs# pass 16 fail 0
$ node --test test/evidence.test.mjs          # fail 1: Error: Cannot find module 'prom-client'  (environment: no node_modules; not a code defect)
$ npm run -s test:vectors
ok: signed payload vectors (valid=8 invalid=37 fields=15)
ok: 5 shared vector files, one iOS copy each, no other copies
```
Integration tests (Postgres, SoftHSM) could not run: no pg, no SoftHSM binary, no pkcs11js.

### 2.1 Signature-encoding experiment (`tmp_B/der.mjs`)
```
canonical                      node.verify: true   derToRaw: accept  SoftwareHsm.verifySignature: true
trailing 0x00                  node.verify: false  derToRaw: reject  SoftwareHsm.verifySignature: false
long-form seq length (BER)     node.verify: false  derToRaw: reject  SoftwareHsm.verifySignature: false
high-S (n-s) DER               node.verify: true   derToRaw: accept  SoftwareHsm.verifySignature: true
high-S raw  SoftwareHsm raw: true  node p1363: true
raw 65 bytes -> false
r=0,s=0 raw -> false
verifier low-S problems: []
verifier high-S problems: [] distinct sig bytes: true
verifier BER trailing problems: [ 'device signature does not verify over the signed bytes' ]
```

### 2.2 Curve-pinning experiment (`tmp_B/curve.mjs`)
```
rsa  verifier problems: []  SoftwareHsm.verifySignature: true
ec P-384 verifier problems: []  SoftwareHsm.verifySignature: true
```

### 2.3 Synthetic chain tampering against `scripts/lib/evidence.mjs` (`tmp_B/chain.mjs`)
Chain: 1 CREDENTIAL_ENROLLED + 4 AUTHORIZATION records, sealed with a software P-256 key (same construction as test/integration/support/syntheticEvidence.mjs).
```
MISSED   baseline (untampered)                                       <- expected: no problem
DETECTED modify sealed field  -> evidence hash does not match the sealed payload
MISSED   modify unsealed export column transactionReference          <- column not in real exports; see B-13
DETECTED modify + recompute hash (no key) -> HSM seal does not verify
DETECTED delete middle record -> chain position 4 where 3 was expected
MISSED   truncate tail, no head given                                <- B-05
DETECTED truncate tail, --expect-head 5 -> records missing at the end of the chain
MISSED   empty export (all deleted), no head                         <- B-05
MISSED   reorder array                                               <- correct: verifier sorts by chainSequence, then links verify
DETECTED duplicate a record -> chain position 3 where 4 was expected
DETECTED duplicate sequence number (column) -> chain position differs between record and payload
DETECTED insert record from other NEXUS ID -> chain broken
MISSED   whole chain of other NEXUS ID (auditor asked for N0000001A) <- B-10
DETECTED chain sealed by wrong HSM key -> HSM seal does not verify with the evidence key it names
DETECTED record without sealedPayload -> unsupported or missing sealed payload
standalone ok: []
standalone record of another customer/bank (no expected id input): ACCEPTED   <- B-10
export column schemaVersion=2: [ 'record metadata does not match the sealed payload (schemaVersion)' ]
```
CLI (`node scripts/verify-evidence.mjs`):
```
chain.json --public-keys=keys.pem         -> EVIDENCE_VALID records=5 ... chain=linked head=not_checked   exit=0
chain_trunc.json --public-keys=keys.pem   -> EVIDENCE_VALID records=4 ... chain=linked head=not_checked   exit=0
chain_trunc.json ... --expect-head=5:<h>  -> INVALID records missing at the end of the chain ...       exit=1
chain.json (no --public-keys)             -> exit=3
empty.json {"records":[]} --public-keys   -> EVIDENCE_VALID records=0 hsm_seal=verified device_signatures=0/0 verified chain=linked head=not_checked  exit=0
```
The verifier needs no database (pure Node, no Auth Core imports) — confirmed.

## 3. Findings

No Critical or High findings were confirmed.

| ID | Sev | Title | Location | Status |
|---|---|---|---|---|
| B-01 | Medium | Synchronous PKCS#11 calls run on the event loop with no deadline; the "every operation has a deadline" claim is partial | src/crypto/pkcs11HsmAdapter.ts:99,120-129,137,284-305 | Confirmed (code); hang behaviour on a real HSM unverified |
| B-02 | Medium | Evidence signing key is not required to be HSM-generated / never-extractable (KEK is) | src/crypto/pkcs11HsmAdapter.ts:345-356 vs masterKeyVault.ts:211 | Confirmed |
| B-03 | Medium | `sealCredentialBaseline` CLI silently uses the software HSM (no posture check); seals are permanent | src/cli/sealCredentialBaseline.ts:22-24, src/crypto/selectHsmAdapter.ts:13, env.ts:185 | Confirmed |
| B-04 | Medium | Evidence is produced only for successful authorizations; credential state, rejection reason and bank are not sealed | src/services/evidenceService.ts:239-274, authorizationConfirmation.ts (recordEvidence `result: 'VERIFIED'`) | Confirmed |
| B-05 | Medium | Verifier returns `EVIDENCE_VALID`/exit 0 for tail-truncated and empty chains when no head is supplied; export's own `head` ignored | scripts/verify-evidence.mjs:335-361, scripts/lib/evidence.mjs:227-234 | Confirmed (executed) |
| B-06 | Low | High-S ECDSA signatures accepted everywhere (malleability) | softwareHsmAdapter.ts:14, pkcs11HsmAdapter.ts:112-130, lib/evidence.mjs:169, authorizationEvidenceCheck.ts:642 | Confirmed (executed) |
| B-07 | Low | Independent verifier and server evidence check do not pin curve/algorithm of the device key (RSA, P-384 verify) | lib/evidence.mjs:169-171, authorizationEvidenceCheck.ts:642, softwareHsmAdapter.ts:14 | Confirmed (executed) |
| B-08 | Low | `reinitialize()` calls `C_Finalize` while other sessions may have calls in flight (undefined behaviour per PKCS#11) | pkcs11HsmAdapter.ts:274-282 | Suspected |
| B-09 | Low | Rewrap "only within the tool's transaction" flag is a session GUC any app-role session can set | migrations/020_secret_key_rotation.sql:14-16,29-30 | Confirmed (code) |
| B-10 | Low | `verify-evidence.mjs` cannot bind the export to an expected NEXUS ID / authorization / bank; sealed payload has no bank identifier | scripts/verify-evidence.mjs:294-335, evidenceService.ts:182-190 | Confirmed (executed) |
| B-11 | Low | Legacy unbound webhook ciphertext format (`iv$tag$ct`, no AAD) is accepted indefinitely | src/crypto/secretBox.ts:332-345 | Confirmed (code) |
| B-12 | Low | Docs overstate: ADR 0004 names nonexistent `sealEvidence`, claims removal always breaks the chain; runbook says every sign/verify has a deadline | docs/adr/0004…md:19,26; docs/operations/runbooks/hsm-unavailable.md:14 | Confirmed |
| B-13 | Info | Unsealed metadata in exports (`hsmKeyVersion`, `createdAt`, `evidenceId`) is not covered by any check | evidenceService.ts:374-391; hsm-key-management.md:29 | Confirmed |
| B-14 | Info | Evidence key has no domain separation: seals and health probes are both ECDSA-SHA256 over a 32-byte value | evidenceService.ts:192, pkcs11HsmAdapter.ts:153-154 | Confirmed (not exploitable today) |
| B-15 | Info | Canonical JSON is "JS `JSON.stringify` with sorted keys", not RFC 8785; non-JS verifiers can diverge on integer-like keys/number formatting | lib/evidence.mjs:5-12, canonicalAuthorization.ts:104 | Suspected (no integer-like keys found in sealed fields) |
| B-16 | Info | Master keys never zeroized; software dev adapter key is per-process | masterKeyVault.ts:97-139, softwareHsmAdapter.ts:7 | Confirmed (documented for master keys) |

---

### B-01 (Medium) Synchronous PKCS#11 calls on the event loop, outside the deadline

What the code does:
```ts
// pkcs11HsmAdapter.ts:19-22 (header)
// - Sign and verify run on a pool of logged-in sessions through the async
//   pkcs11js calls, so the event loop is never blocked by the HSM, and every
//   operation has a deadline (HSM_OPERATION_TIMEOUT_MS).
// :99
this.pkcs11.C_SignInit(session.handle, { mechanism: Pkcs11js.CKM_ECDSA_SHA256 }, session.privateKey);
const raw = await this.pkcs11.C_SignAsync(...)
// :120  C_CreateObject(...)  :129 C_VerifyInit(...)  :137 C_DestroyObject(...)
// :284-305 openSession(): C_GetSlotList, C_GetTokenInfo, C_OpenSession, C_Login, C_FindObjects*, C_GetAttributeValue — all sync
// :183-189
const pending = work(session);            // sync part of work() runs here, before the race
...
const result = await Promise.race([pending, deadline]);
```
Why wrong: only `C_SignAsync`/`C_VerifyAsync` run on libuv workers. Every other PKCS#11 call — including `C_Login`, `C_FindObjects` and `C_SignInit`, which on a network HSM are round trips — executes on the main thread before the deadline timer exists (`work(session)` runs synchronously up to its first `await`; `acquire()` → `openSession()` is fully synchronous). The test `hsm.test.mjs:102` hangs only `C_SignAsync`.

Failure scenario: a network HSM (Luna/nShield over TCP) stalls during a session open after failover. `openSession()` blocks the Node event loop: every HTTP request, `/healthz`, webhook/expiry workers freeze for the duration of the vendor client's own timeout (often tens of seconds or unbounded). The documented fail-fast (`stuckCalls`) never triggers because nothing is "stuck" in the async sense.

Fix: in `Pkcs11HsmAdapter`, open and log in sessions eagerly at construction/health-check time (pre-fill the pool) so request paths never call `openSession()` synchronously; move `C_SignInit`/`C_VerifyInit`/`C_CreateObject` into a worker (e.g. a `worker_threads` HSM worker owning the module) or, minimally, start the deadline timer before `work(session)` and document that init calls are not bounded. Correct the header comment and runbook line 14.

Regression test: in `hsm.test.mjs`, a Proxy that makes `C_OpenSession` (and separately `C_SignInit`) busy-wait 2 s; assert that a concurrent `setImmediate` callback / unrelated HTTP request completes in < 200 ms and that `signEvidence` rejects with `HsmTimeoutError` within `operationTimeoutMs + ε`.

### B-02 (Medium) Evidence key provenance not enforced

```ts
// pkcs11HsmAdapter.ts:346-355
{ type: CKA_KEY_TYPE }, { type: CKA_SIGN }, { type: CKA_SENSITIVE }, { type: CKA_EXTRACTABLE }, { type: CKA_EC_PARAMS }
...
if (!isTrue(sensitive)) throw ...; if (isTrue(extractable)) throw ...
```
vs the KEK:
```ts
// masterKeyVault.ts:211
if (!flag(6) || !flag(7)) fail(`KEK '${label}' must have been generated in the HSM and never been extractable (CKA_LOCAL, CKA_NEVER_EXTRACTABLE)`);
```
Why wrong: the whole evidence model (ADR 0004 "the holder of a device key … cannot place a record in the sealed chain"; bank pinned evidence keys) rests on the evidence private key existing only in the HSM. An EC key imported with `C_CreateObject` from a known value, or one that was extractable and later flipped to non-extractable, passes these checks. The codebase already recognised this exact gap for the KEK (`master-key-hsm.test.mjs:213` "a KEK imported from a known value … is refused") but not for the more important signing key.

Scenario: during setup, the evidence key is generated with OpenSSL "for backup" and imported; a copy on an admin laptop can forge seals indistinguishable from Auth Core's for every bank pinning that key.

Fix: in `assertEvidencePrivateKey`, also read `CKA_LOCAL`, `CKA_NEVER_EXTRACTABLE`, `CKA_ALWAYS_SENSITIVE` and refuse unless all true (allow an explicit, logged override only for vendor backup/clone schemes that reset `CKA_LOCAL`, documented in the key ceremony).

Regression test: `hsm.test.mjs` — import an EC private key with `C_CreateObject` (`CKA_SENSITIVE=true, CKA_EXTRACTABLE=false`) under the evidence label; assert `new Pkcs11HsmAdapter(...).healthCheck()` rejects mentioning `CKA_LOCAL`/`CKA_NEVER_EXTRACTABLE`.

### B-03 (Medium) Baseline CLI can seal with a throw-away software key

```ts
// selectHsmAdapter.ts:7-13
if (env.HSM_ADAPTER === 'pkcs11') { ... return new Pkcs11HsmAdapter(); }
return new SoftwareHsmAdapter();
// env.ts:185
HSM_ADAPTER: z.enum(['software', 'pkcs11']).default('software'),
// sealCredentialBaseline.ts:22-24 — no configurationErrors()/productionBlockers() call
const hsm = await selectHsmAdapter(); await hsm.healthCheck(); configureEvidenceKeyring(hsm);
```
Only `server.ts:31-43` runs the posture checks. The CLI, run with an env file missing `HSM_ADAPTER=pkcs11` (default `software`), seals one `CREDENTIAL_ENROLLED` record per active credential with an in-memory key generated in `softwareHsmAdapter.ts:7` and discarded at exit.

Consequence: `evidence_records` is append-only and `credentials.enrolment_evidence_id` can be attached only once (migration 020 trigger: "the enrolment record is attached once"). Every migrated credential then fails `sealProblem` ("sealed with an unknown evidence key") forever; each affected NEXUS ID chain also permanently contains a record no verifier can validate. Recovery requires re-enrolment of every customer. Not a forgery, but an irreversible production outage from one mis-set variable.

Fix: make `selectHsmAdapter()` refuse `software` unless `NODE_ENV !== 'production' && env.ALLOW_INSECURE_DEVELOPMENT` (same rule as `insecureDevelopmentSettings`), and have every CLI that seals call `configurationErrors`/`productionBlockers`. Optionally remove the `software` default.

Regression test: unit test loading `selectHsmAdapter.ts` with `NODE_ENV=production`, `HSM_ADAPTER` unset → rejects; with `NODE_ENV=test` and no `ALLOW_INSECURE_DEVELOPMENT` → rejects.

### B-04 (Medium) Evidence record does not match the product claim

Product claim fields vs sealed payload (`evidenceService.ts:239-259`):

| Claimed | Sealed? |
|---|---|
| request_id | yes (`authorizationId`) |
| credential_id | yes |
| transaction_reference | yes |
| canonical_hash | yes (`canonicalPayloadHash`, plus the signed bytes) |
| signature | yes (+ format, algorithm, device public key) |
| verified_at | yes (`verifiedAt`) |
| credential_state | **no** — only `attestationVerdict`; no revocation/replacement record type exists |
| channel | partial — only in `verificationFactors[].channel` (adaptive verification sessions), not the confirmation channel (online/offline is `confirmationMethod`) |
| policy | yes (`policyReference`, `policyVersion`) |
| result | always the literal `'VERIFIED'` (`authorizationConfirmation.ts` recordEvidence `result: 'VERIFIED'`) |
| reason | **no** |
| bank / client id | **no** — not in the sealed payload, nor in the device-signed bytes |

Rejected, expired, failed (INVALID_SIGNATURE) decisions are written only to `authorization_attempts` and `audit_logs` (`authorizationConfirmation.ts` countFailedAttempt), which are not sealed or chained. A dispute of the form "the customer says they rejected it" or "the device was revoked before this" cannot be answered from evidence; revocation is provable only through the bank's own registry (bankTrust.mjs), not Auth Core evidence.

Fix: either narrow the product claim to "evidence of confirmed authorizations", or add record types `AUTHORIZATION_REJECTED/EXPIRED` and `CREDENTIAL_REVOKED` appended in the same transaction as the state change, sealing `result`, `reason`, `credentialState` and `clientId`; extend `verifyEvidenceChain` to refuse an AUTHORIZATION after its credential's revocation record.

Regression test: integration test revoking a credential and then attempting a confirmation; assert the chain contains `CREDENTIAL_REVOKED` and `verifyEvidenceChain` flags a hand-built AUTHORIZATION sealed after it.

### B-05 (Medium) Verifier reports VALID (exit 0) for truncated and empty chains

```js
// verify-evidence.mjs:357-361
const pinned = Boolean(keyFile);
console.log(`${pinned ? 'EVIDENCE_VALID' : 'EVIDENCE_SELF_CONSISTENT'} ... ${expectedHead ? ' head=matched' : isChain && heads.length === 0 ? ' head=not_checked' : ''}...`);
if (!pinned) process.exitCode = 3;
```
Executed (§2.3): dropping the last record, or exporting `{"records":[]}`, yields `EVIDENCE_VALID … head=not_checked`, exit 0. The export's own `head` field (`routes/nexusV1.ts:131`) is ignored, so even a paged export (limit 1000, `evidenceService.ts:346`) that contains only the first page verifies as valid. The project already chose a distinct exit code (3) for "keys not pinned" precisely so scripts cannot mistake a weaker result for an independent one; an unchecked head is the same class of weakness but returns 0. The doc caveat exists (evidence-format.md:220,272) but ADR 0004:26 says removal "breaks the chain".

Fix: in `verify-evidence.mjs`, for chain exports without `--expect-head`/`--heads`, exit with a distinct non-zero code (e.g. 4, `EVIDENCE_VALID_HEAD_UNCHECKED`); always compare against `exported.head` when present and report `records missing` if `head.chainSequence` exceeds the last record; treat `records.length === 0` as invalid.

Regression test: `evidence.test.mjs` — spawn CLI on a 5-record chain minus last record without head → exit ≠ 0; with `exported.head` = record 5 → INVALID.

### B-06 (Low) High-S signatures accepted (malleability)

No low-S check anywhere (`derToRaw` checks encoding only, ecdsaSignatureFormat.ts:17-31). Executed: for a valid (r,s), (r, n−s) verifies in `SoftwareHsmAdapter`, Node, and `verifyDeviceSignature`. Consequence for evidence uniqueness is limited: one evidence record per `authorization_id` (UNIQUE, schema.sql:171) and the authorization is consumed once, so a mauled signature cannot create a second record. Residual: a third party holding a record can produce a different-bytes signature that equally verifies; `submitDeferredSignature` compares stored signature bytes for idempotency (`stored.signature === signatureB64`), so a mauled resubmission is reported as a conflict instead of ALREADY_RECORDED. Fix: normalise to low-S on receipt (store `s = min(s, n−s)`) or reject high-S in `derToRaw`/raw path if both SDKs emit low-S (Secure Enclave/Keystore do not guarantee it — normalise, do not reject). Test: crypto.test.mjs high-S vector → normalised value stored/compared.

### B-07 (Low) Device key algorithm not pinned at verification time

`lib/evidence.mjs:169` and `authorizationEvidenceCheck.ts:642` call `verify('sha256', …, { key: pem, … })` with whatever key the sealed payload holds; executed: an RSA-2048 and a P-384 key pass `verifyDeviceSignature`. Registration enforces P-256 (`p256PublicKey.ts:16-33`), but `sealCredentialBaseline.ts:30-36` seals `public_key_pem` from the DB without `parseP256PublicKey`, and an auditor should not have to trust that. Fix: in `verifyDeviceSignature` and `authorizationEvidenceCheck`, require `asymmetricKeyType==='ec' && namedCurve==='prime256v1'`; in the baseline CLI run `parseP256PublicKey`. Test: verifier rejects RSA/P-384 device keys.

### B-08 (Low, Suspected) `C_Finalize` with calls in flight

`reinitialize()` (pkcs11HsmAdapter.ts:274-282) finalises the module while other pooled sessions may be inside `C_SignAsync` on worker threads. PKCS#11 v2.40 §5.4 states C_Finalize behaviour is undefined while other threads are making calls; vendor libraries can crash the process. Confirm with a vendor HSM / SoftHSM stress test (parallel signs while forcing `CKR_CRYPTOKI_NOT_INITIALIZED`). Fix: drain (wait for `openSessions - idle.length` in-flight calls) before finalising, or never finalise in-process and restart instead.

### B-09 (Low) Rewrap bypass flag is user-settable

`secret_rewrap_allowed()` reads `current_setting('nexus.secret_rewrap', true)`; any `nexus_app` session can `SELECT set_config('nexus.secret_rewrap','on',true)` and then replace `offline_secret_encrypted`. Because the ciphertext's AAD binds `device:<credentialId>` (secretBox.ts:294-296), only another valid ciphertext of the same credential can be substituted, so the impact is small; but the migration comment ("only within its own transaction") overstates the control. Fix: perform rewrap through a `SECURITY DEFINER` function owned by `nexus_owner` that checks the decrypt-equality server-side is impossible; realistically, document that the trigger does not protect against the app role, or use a dedicated rotation role whose membership the trigger checks (`pg_has_role`). Test: db-roles test that `nexus_app` setting the GUC cannot update the column.

### B-10 (Low) Verifier has no "expected subject" input

`verify-evidence.mjs` accepts any valid export and prints `VALID` lines; there is no `--nexus-id`/`--authorization-id`. Executed: a valid chain of another NEXUS ID, and a standalone record of another customer, verify. The sealed payload contains no bank/client identifier, so a multi-bank deployment sharing one evidence key cannot prove which bank a record belongs to. The bank-side decision (`bankTrust.mjs:107-123`) does bind `authorizationId`/`nexusId`, so this affects auditors using the generic CLI. Fix: add `--expect-nexus-id`, `--expect-authorization-id`, and seal `clientId` in `appendRecord`. Test: CLI with mismatched `--expect-nexus-id` exits 1.

### B-11 (Low) Legacy unbound webhook ciphertext accepted forever

```ts
// secretBox.ts:334-340
const legacyWebhookUnbound = purpose === 'webhook' && parts[0] !== 'v2';
... return open(key.key, body, legacyWebhookUnbound ? null : aad);
```
A DB writer can copy a remaining 1.4-format webhook secret of bank A into bank B's row; it decrypts for B (no AAD), so B's deliveries are HMAC'd with A's key. Only matters while legacy rows exist; `rotateSecretKeys` converts them to `k1` with AAD. Fix: after rotation, reject non-`k1` formats (config flag `ACCEPT_LEGACY_SECRET_FORMATS=false` default in production). Test: secret-box.test with legacy value and flag off → throws.

### B-12 (Low) Docs vs code

- ADR 0004:19 — "`sealEvidence` in `evidenceService.ts`": no such function; it is `appendRecord` (evidenceService.ts:167). Wrong.
- ADR 0004:26 — "Removing, reordering or substituting a record breaks the chain or a seal": tail removal does not (B-05). Overstated; evidence-format.md:272 states it correctly.
- hsm-unavailable.md:14 and pkcs11HsmAdapter.ts:19-22 — "Every sign and verify runs through the asynchronous PKCS#11 calls … with a deadline": partial (B-01).
- migration 009 header: "rejected for every role, including the owner" — the owner can `ALTER TABLE … DISABLE TRIGGER` (migration 013 does exactly that). roles.sql and ADR 0004 state the limit correctly; the migration comment is wrong.
- KEY_MANAGEMENT.md — dual control, key ceremony, backup/restore are explicitly marked "Documented only; not exercised" / "Not done" / BLOCKED (lines 104-105, 138): accurate, not a defect, but they are MISSING in code.
- hsm-key-management.md:13 lists exactly the attributes the code checks: accurate (but see B-02).

### B-13 / B-14 / B-15 / B-16 (Info)
- B-13: `hsmKeyVersion` comes from config and is documented "not derived or checked" (hsm-key-management.md:29); `createdAt`/`evidenceId` are unsealed. Readers must rely on sealed `verifiedAt`/`sealKeyId` only.
- B-14: seal = ECDSA-SHA256(evidenceHash bytes); healthCheck signs SHA-256("NEXUS-SIGN-HSM-HEALTH-CHECK") with the same key (pkcs11HsmAdapter.ts:153). The probe signature is a valid seal over a hash with no canonical-JSON preimage, so unusable; add a domain prefix (e.g. sign `"NEXUS-SIGN-EVIDENCE-v3" || hash`) at the next schema bump.
- B-15: both canonicalisers are `JSON.stringify(sortedKeys)`. JS orders integer-like keys first, so a non-JS verifier sorting lexicographically would differ if any sealed object (e.g. `attestation.material`, `verificationFactors`) ever has such keys. The authorization bytes explicitly forbid them (canonicalAuthorization.ts BENEFICIARY_KEY_PATTERN); the sealed payload does not. Specify the canonical form in evidence-format.md or adopt RFC 8785.
- B-16: master keys stay in `loaded` for process life (documented, KEY_MANAGEMENT.md:150). `SoftwareHsmAdapter` generates its key per process (softwareHsmAdapter.ts:7), so any dev restart makes all sealed enrolments unverifiable — expected for dev, worth a startup log line.

## 4. Security properties verified as correctly implemented

| Property | Location | Covering test |
|---|---|---|
| Device ECDSA fixed to SHA-256; device keys restricted to uncompressed P-256 SPKI at registration (strict PEM, exact SPKI prefix, Node validates point on curve) | p256PublicKey.ts:16-33; pkcs11HsmAdapter.ts:114,125-126 (CKA_EC_PARAMS = P-256 OID) | crypto.test.mjs "device public keys: only uncompressed P-256 SPKI" (pass) |
| Strict DER: trailing bytes, long-form lengths, negative and non-minimal INTEGERs, >32-byte components rejected; raw must be exactly 64 bytes | ecdsaSignatureFormat.ts:17-31,33-36,62-98 | crypto.test.mjs "DER to raw accepts only the canonical encoding"; §2.1 |
| Verification never accepts on error (malformed key/signature → false; unexpected HSM errors throw, not true) | softwareHsmAdapter.ts:12-17; pkcs11HsmAdapter.ts:107-139; lib/evidence.mjs:41-46,168-174 | crypto.test.mjs "software HSM: malformed …"; hsm.test.mjs:62 (not run) |
| No silent fallback from PKCS#11 to software in the server; production refuses `HSM_ADAPTER=software`, missing PIN/module/token label/key label, `MASTER_KEY_SOURCE≠hsm` | productionPosture.ts:14-16,34,51-57; server.ts:31-57 | production-posture.test.mjs (16 pass) |
| Evidence private key checked EC/P-256/CKA_SIGN/SENSITIVE/not EXTRACTABLE; unique label/ID; public key must match (self-test) | pkcs11HsmAdapter.ts:324-356,152-158 | hsm.test.mjs:85,92 (not run) |
| AES-256-GCM, 96-bit random IV, 128-bit tag enforced on decrypt, AAD = purpose:owner (credentialId / `push:`credentialId / username / clientId) | secretBox.ts:298-313,294-296 + call sites (clientService.ts:34,85; deviceKeysService.ts:48; pushRegistrationService.ts:102,169; adminAuthService.ts:58,105) | secret-box.test.mjs (pass) |
| KEK: AES-256, sensitive, non-extractable, CKA_LOCAL + NEVER_EXTRACTABLE, purpose-bound AAD per master-key name; IV = HSM RNG XOR Node RNG | masterKeyVault.ts:59-95,198-230 | master-key-hsm.test.mjs:189,196,213 (not run) |
| Interrupted rotation safe: preflight decrypt-all, per-batch transaction, compare-and-swap UPDATE, round-trip check | rotateSecretKeys.ts:44-72,75-87 | key-rotation-interrupted.test.mjs (not run) |
| Evidence sealed atomically in the same transaction as the VERIFIED state change, with the outbox head webhook | authorizationConfirmation.ts finalizeVerified (UPDATE … then recordEvidence(tx,…)); evidenceService.ts:195-217 | evidence-checkpoints.test.mjs:41 (not run) |
| Per-NEXUS-ID chain, advisory lock, unique (nexus_id, chain_sequence), unique predecessor, single genesis; UPDATE/DELETE/TRUNCATE triggers; app role lacks UPDATE/DELETE on evidence | evidenceService.ts:175-179; schema.sql:205-229; migrations/013; scripts/db/roles.sql | evidence-integrity.test.mjs:99, db-roles.test.mjs (not run) |
| Seal binds schemaVersion, recordType, nexusId, chainSequence, previous hash, sealKeyId and body; verifier checks hash, seal (with key named by sealKeyId), metadata columns, position, links, enrolment provenance, device signature over the exact signed bytes | evidenceService.ts:182-193; lib/evidence.mjs:66-112,198-236 | §2.3; evidence.test.mjs (blocked here by missing prom-client) |
| Server re-checks evidence before commit (seal, metadata, position, predecessor, stored terms, enrolled key, device signature) | authorizationEvidenceCheck.ts:30-91 | evidence-forgery-hsm.test.mjs, evidence-metadata-binding.test.mjs (not run) |
| Credential keys compared to sealed enrolment on every use; cache keyed by exact hash+signature | credentialIntegrity.ts:66-101 | evidence-integrity.test.mjs:22 (not run) |
| Verifier does not trust export keys: exit 3 without `--public-keys` | verify-evidence.mjs:353-361 | §2.3 (exit=3) |
| JWS: ES256 only, no `none`/jwk/jku/x5c/x5u/crit, 64-byte signature | jws.ts:36-62 | not covered in the tests I ran |
| Passwords: scrypt N=2^17 r=8 p=1 (admin), N=2^14 (256-bit client secrets), constant-time compare, rehash on login, dummy verify for unknown users | password.ts:21-80 | admin-totp.test.mjs (pass, partial) |
| TOTP: RFC 6238 SHA-1/30 s/6 digits, ±1 step, replay refused via stored last step with conditional UPDATE | totp.ts:54-64; adminAuthService.ts:104-113 | admin-totp.test.mjs (pass) |
| No Math.random in src/scripts; no hard-coded production keys; `.env.example`/compose contain only empty or local-dev values; pino redacts auth headers/bodies | grep results; server.ts:18-28 | — |

## 5. Engineering-quality notes (files read)
- `HsmAdapter` mixes two unrelated duties (device-signature verification and evidence sealing). Device verification in the HSM costs `C_CreateObject`/destroy per call while `credentialIntegrity`, `authorizationEvidenceCheck` and the verifier all use Node `verify` anyway; the HSM path adds latency and failure modes (B-01) without a security gain.
- `mapEvidenceRow` (evidenceService.ts:372) is an exported one-line wrapper of `mapEvidence`; export `mapEvidence` instead.
- Duplicated constants: `P256_SPKI_PREFIX` in p256PublicKey.ts:5 and pkcs11HsmAdapter.ts:59; `sameKey`/`spki` helpers in credentialIntegrity.ts:139-146, lib/evidence.mjs:21-28, and inline in authorizationEvidenceCheck.ts:637; three copies of `CK_ULONG` parsing/slot selection across pkcs11HsmAdapter.ts, masterKeyVault.ts, cli/masterKeys.ts.
- Two stacked doc comments on `EnrolmentReason` (evidenceService.ts:81-84).
- `ulong()` assumes little-endian (pkcs11HsmAdapter.ts:385-389) — documented but not checked (`os.endianness()`).
- Empty catches are all commented and best-effort (close/destroy); none swallow a verification result.

## 6. Feature status

| Feature | Status |
|---|---|
| P-256/SHA-256 device signature verification, strict DER | IMPLEMENTED |
| Low-S normalisation | MISSING |
| Curve pinning in independent verifier | MISSING |
| PKCS#11 evidence sealing (sign, pool, timeouts, re-login, retry) | IMPLEMENTED (code); real-HSM behaviour BLOCKED EXTERNAL; SoftHSM tests UNVERIFIED here |
| Bounded HSM latency for all PKCS#11 calls | PARTIAL (B-01) |
| Evidence key provenance (CKA_LOCAL/NEVER_EXTRACTABLE) | MISSING (B-02) |
| Production refusal of software HSM (server) | IMPLEMENTED |
| Production refusal of software HSM (CLIs) | MISSING (B-03) |
| AES-256-GCM secret box with AAD and key IDs | IMPLEMENTED |
| HSM-wrapped master keys (KEK in HSM, master keys in process memory) | IMPLEMENTED; vendor HSM BLOCKED EXTERNAL |
| Master keys as non-extractable HSM objects | MISSING (documented) |
| Master key / KEK rotation tooling | IMPLEMENTED |
| Dual control / key ceremony | MISSING (documented as procedure only) |
| HSM backup/restore | MISSING in code; BLOCKED EXTERNAL |
| Evidence hash chain per NEXUS ID, numbered, append-only | IMPLEMENTED |
| External checkpoints (sealed heads to bank via outbox) | IMPLEMENTED; verifier use optional (B-05) |
| Evidence for rejected/expired decisions, credential state, reason, bank id | MISSING (B-04) |
| Independent offline verifier | IMPLEMENTED; tail truncation detection PARTIAL |
| Bank execution decision (pinned keys, bank approvals) | IMPLEMENTED (bank-trust.test pass) |
| Password hashing (scrypt) / admin TOTP with replay protection | IMPLEMENTED |
| SoftHSM test separation from production claims | IMPLEMENTED (suites skip without SoftHSM; KEY_MANAGEMENT.md:103-105 states SoftHSM ≠ production) |

## 7. Memory-relevant notes
None.
