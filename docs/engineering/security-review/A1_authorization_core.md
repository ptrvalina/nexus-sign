# A1 — Authorization core and identity: independent audit

Repository: `nexus-sign` @ `5999984` (2.0.0-rc.2). Read-only static audit plus pure-Node execution (unit loader `test/support/load-ts.mjs`). All paths below are relative to `auth-core/` unless they start with `../`.

## 1. Scope actually read

Read in full:
- `src/routes/nexusV1.ts`, `src/routes/mobileV1.ts`, `src/routes/oauth.ts`, `src/app.ts`, `src/server.ts`
- `src/middleware/auth.ts`, `mobileAuth.ts`, `mtlsGateway.ts`, `bruteForceProtection.ts`, `errorHandler.ts`
- `src/services/authorizationService.ts`, `authorizationConfirmation.ts`, `authorizationRecord.ts`, `authorizationExpiry.ts`, `authorizationEvidenceCheck.ts`, `canonicalAuthorization.ts`, `deviceProtocol.ts`, `deviceKeysService.ts`, `credentialService.ts`, `credentialIntegrity.ts`, `nexusIdentityService.ts`, `clientService.ts`, `tokenService.ts`, `mobileSessionService.ts`, `bankTransactionService.ts`, `attestationBinding.ts`, `attestationVerificationService.ts`, `requestContext.ts`, `errors.ts`, `src/types/index.ts`, `src/workers/expiryWorker.ts`
- Support read as needed: `src/db/pool.ts`, `src/db/redis.ts`, `src/crypto/tokenDigest.ts`, `src/crypto/p256PublicKey.ts`, `src/crypto/ecdsaSignatureFormat.ts`, `src/crypto/softwareHsmAdapter.ts`, `src/crypto/hsmAdapter.ts`, `src/crypto/pkcs11HsmAdapter.ts` (verifySignature only), `src/config/productionPosture.ts`, `src/config/env.ts` (relevant keys), `src/services/evidenceService.ts` (getEvidenceChain, getChainHead, getEvidenceForAuthorization, getAuthorizationEvidencePosition)
- Schema: `src/db/schema.sql` lines 25–125, 425–520, 549–626 (identity/credential/authorization tables, lifecycle trigger, one-active-credential index)
- Docs: `../docs/protocol/authorization-protocol-v1.md` (object, encoding, signature sections), relevant parts of `device-authentication-and-offline-confirmation.md` and `offline-confirmation-v2-deferred-signature.md`
- Tests: `test/gateway-and-webhooks.test.mjs` (exemption test), test runner output.

Skimmed / not read in depth (could-not-verify where relevant):
- `src/services/appAttestService.ts`, `androidKeyAttestation.ts`, `playIntegrityService.ts` — only their call contracts via `attestationVerificationService.ts`; the parsers themselves (CBOR, ASN.1 key description, JWS) were **not** audited.
- `migrations/*` — not read; the consolidated `schema.sql` was used for invariants (owned by the DB auditor).
- `adaptiveVerificationService.ts`, `pushService.ts`, `verificationCall.ts`, `recoveryService.ts`, `evidenceService.ts` (sealing) — outside scope; only their interaction with the authorization path was followed.

Executed:
- `npm run -s test:vectors` → `ok: signed payload vectors (valid=8 invalid=37 fields=15)`, `ok: 5 shared vector files`.
- `node --test` on `protocol`, `device-protocol`, `crypto`, `regression-2.0`, `property-fuzz`: all pass. `low-findings`, `mobile-session`: fail with `Cannot find module 'pg'` (environmental, not a defect).
- Ad-hoc scripts (in the scratchpad, not in the repo) exercising `isDeviceFacingRequest`, `hashCanonicalAuthorization`, `SoftwareHsmAdapter.verifySignature`, `derToRaw`. Results quoted in the findings.

## 2. Findings table

| ID | Severity | Title | Location | Status |
|---|---|---|---|---|
| A1-01 | **High** | Deferred-signature upload (offline v2) is blocked by the mTLS gateway gate in production: every offline confirmation ends `OFFLINE_UNSIGNED` | `src/middleware/mtlsGateway.ts:16-34`, `src/app.ts:93`, `src/routes/mobileV1.ts:377` | Confirmed |
| A1-02 | Medium | Displayed-text controls are incomplete: no Unicode normalization, confusables/mixed-script, full-width digits, or internal space runs; padding check only on beneficiary | `src/services/canonicalAuthorization.ts:38,50,52-73` | Confirmed (acceptance executed) |
| A1-03 | Medium | No customer "reject / it wasn't me" action, and no bank cancel of a pending authorization | `src/routes/mobileV1.ts` (absent), `src/routes/nexusV1.ts` (absent) | Confirmed |
| A1-04 | Medium | `POST /v1/nexus-identities` is not idempotent and there is no lookup by `bankCustomerRef`: a lost response orphans the identity | `src/services/nexusIdentityService.ts:40-78`, `src/routes/nexusV1.ts:100-106` | Confirmed |
| A1-05 | Low | ECDSA high-S signatures accepted (malleable); the protocol doc implies a single canonical signature | `src/crypto/softwareHsmAdapter.ts:9-17`, `src/crypto/pkcs11HsmAdapter.ts:106-135`, `src/crypto/ecdsaSignatureFormat.ts` | Confirmed (executed, software adapter) |
| A1-06 | Low | Idempotency replay comparison ignores `expiresInSeconds`, `verificationPolicy`, `correlationId`, `pushNotification` | `src/services/authorizationService.ts:143-158` | Confirmed |
| A1-07 | Low | Lock-order inversion between credential revocation and confirmation can deadlock (fails closed as 500) | `src/services/credentialService.ts:168-185` vs `src/services/authorizationConfirmation.ts:289-338` | Suspected |
| A1-08 | Low | `withTransaction` loses the original error and returns a possibly broken client to the pool when `ROLLBACK` fails | `src/db/pool.ts:16-31` | Confirmed |
| A1-09 | Low | Bank access tokens carry no scope/audience; one token reaches every bank endpoint, incl. verification-result completion and push messaging | `src/services/tokenService.ts:23-54`, `src/middleware/auth.ts:21-45` | Confirmed |
| A1-10 | Low | No request rate limiting on bank or device APIs beyond per-authorization attempt counters | `src/app.ts:116-124` | Confirmed |
| A1-11 | Info | Inconsistent error semantics: signature failure is HTTP 200 `{status:FAILED}`, deferred failure is 422/409, expiry 410 | `src/routes/nexusV1.ts:219,240`, `src/routes/mobileV1.ts:368,384` | Confirmed |
| A1-12 | Info | `GET /v1/authorizations/:id` spreads the whole record (signature, nonce, offline reasons) to the bank | `src/routes/nexusV1.ts:199-201` | Confirmed |
| A1-13 | Info | Canonical object carries no bank/tenant field; tenant binding relies on the globally unique `authorization_id`/`nexus_id` | `src/services/canonicalAuthorization.ts:6-22` | Confirmed (not exploitable) |
| A1-14 | Info | Engineering: dead `REJECTED` branch, orphan JSDoc, redundant gateway middleware, integrity reason leaked in 403 body, others | see §3.14 | Confirmed |

Counts: High 1, Medium 3, Low 6, Info 4. No Critical.

## 3. Findings in detail

### A1-01 (High) — Offline v2 deferred signature cannot reach Auth Core in production

**What the code does.** The global gateway gate runs before every router:

```ts
// src/app.ts:93
app.use(requireGatewayMtls);
```

```ts
// src/middleware/mtlsGateway.ts:53-63
export function requireGatewayMtls(req, res, next) {
  if (!env.REQUIRE_MTLS_HEADER || isDeviceFacingRequest(req)) { next(); return; }
  const remote = normalizeIp(req.socket.remoteAddress);
  if (env.TRUSTED_PROXY_IPS.length === 0 || !remote || !env.TRUSTED_PROXY_IPS.map(normalizeIp).includes(remote)) {
    res.status(403).json({ error: 'mTLS gateway required' }); return;
  }
  if (req.header(env.MTLS_VERIFIED_HEADER) !== 'SUCCESS') { res.status(403)... }
```

The exemption list `DEVICE_ROUTES` (`mtlsGateway.ts:16-34`) lists `.../signature`, `.../verification-sessions`, push routes, etc., but **not** `POST /v1/mobile/authorizations/:id/deferred-signature`, the route the SDKs call (`../ios-sdk/Sources/NEXUSSign/NetworkClient.swift:67`, `../android-sdk/src/main/kotlin/com/nexis/nexussign/NetworkClient.kt:104`) and that `mobileV1.ts:377` serves.

Executed: `isDeviceFacingRequest({method:'POST', path:'/v1/mobile/authorizations/<uuid>/deferred-signature'})` → `false`.

`REQUIRE_MTLS_HEADER=true` and `OFFLINE_CONFIRMATION_MODE=deferred_signature` are both **mandatory** in production (`src/config/productionPosture.ts:45,60`). A phone has no bank client certificate, so the request gets `403 mTLS gateway required` before device-signature authentication runs.

**Why it matters / scenario.** Customer confirms at a branch with QR + 8-digit code → `acceptOfflineCode` moves the authorization to `OFFLINE_PROVISIONAL` (`authorizationConfirmation.ts:448-466`). The device queues its signature and uploads it when online → 403 every time. After `OFFLINE_SIGNATURE_DEADLINE_HOURS` (default 72) the sweep moves it to `OFFLINE_UNSIGNED` and sends the bank `authorization.offline_unsigned`, documented as a security event (`authorizationConfirmation.ts:584-610`). Result: the whole offline feature cannot produce a single `VERIFIED` authorization in production, and every genuine offline confirmation raises a false fraud signal. It fails closed (no unauthorized payment), so it is not Critical, but it is a production-only break of an advertised feature that no test catches: the test list in `test/gateway-and-webhooks.test.mjs:8-19` omits the route, and the only integration test that sets `REQUIRE_MTLS_HEADER` is `test/integration/admin-audit-mtls.test.mjs:146`. `offline-deferred-signature.test.mjs` runs with mTLS off.

The PENDING_USER pre-upload path (`submitDeferredSignature` storing a signature before the code arrives, `authorizationConfirmation.ts:538-564`) is blocked the same way.

**Minimal fix.** Add `{ method: 'POST', pattern: /^\/v1\/mobile\/authorizations\/[^/]+\/deferred-signature\/?$/i }` to `DEVICE_ROUTES` in `mtlsGateway.ts`. The route is already protected by `authenticateMobileSession` → `deviceInScope` (`mobileV1.ts:379`) and by the credential check in `submitDeferredSignature` (`authorizationConfirmation.ts:512`), the same as the other exempt device routes.

**Regression tests.**
1. `test/gateway-and-webhooks.test.mjs`: add `['POST', '/v1/mobile/authorizations/<uuid>/deferred-signature']` to `exempt` and `['GET', ...deferred-signature]` to `protectedRoutes`.
2. Run `test/integration/offline-deferred-signature.test.mjs` a second time under `REQUIRE_MTLS_HEADER=true` with `TRUSTED_PROXY_IPS` set, so that device routes go without the gateway headers and bank routes with them. Better still, generate the exemption list from the mobile router's device-authenticated routes and assert they are equal, so the next device route cannot be forgotten.

### A1-02 (Medium) — Displayed-text controls do not cover confusables, normalization or internal spacing

**What the code does.**

```ts
// canonicalAuthorization.ts:38
const PADDED = /^\p{Zs}|\p{Zs}$/u;
// :50
export const DISPLAY_UNSAFE_CHARACTER = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Cs}]/u;
// :61-62 (beneficiary only)
if (PADDED.test(value)) throw ...;
if (DISPLAY_UNSAFE_CHARACTER.test(value)) throw ...;
// :67-73 assertDisplaySafeFields: only DISPLAY_UNSAFE_CHARACTER on top-level strings
```

Executed against `hashCanonicalAuthorization`:
- `beneficiary.name = 'PаyPal Ltd'` (Cyrillic `а`) → accepted.
- `'José'` NFC vs `'José'` NFD → both accepted, different hashes.
- `'a' + 6×U+00A0 + 'b'` (internal run of no-break spaces) → accepted.
- `transaction_reference = ' padded '` → accepted (padding rule only on beneficiary values).
- Full-width digits (`０`–`９`, category Nd) are not refused in any field, including an `iban`/`account` beneficiary value. Inferred from the regex; no beneficiary schema exists.
- U+2028 → refused (correct).

**Why it matters.** Signed bytes = displayed text holds: the SDK renders from the signed bytes (`authorization-protocol-v1.md` §Device-side verification). But the threat this layer exists for is the customer misreading the payee. A payee name or account with homoglyphs, NFD/NFC variants or full-width digits looks identical to a legitimate one on screen. An internal run of spaces can push the account out of a truncated prompt, which is the same harm the code comments cite for line separators. The beneficiary has no typed fields at all (no IBAN format or check digit, no ASCII restriction on account identifiers), so Auth Core cannot assert that the account shown is a well-formed account.

**Scenario.** Malware in web banking replaces a payee with `name: "Allegro sp. z o.о."` (Cyrillic `о`) and an attacker IBAN written partly in full-width digits. Some fonts render the IBAN identically to the expected one. The device shows "the right" payee and the customer signs. The signature is valid and the evidence is sound, but the customer was deceived on exactly the fields dynamic linking is meant to protect.

**Minimal fix** (in `assertValidBeneficiary` / `assertDisplaySafeFields`):
1. Require NFC (`value === value.normalize('NFC')`) for every string field, and specify it in `authorization-protocol-v1.md` and the vectors.
2. Refuse runs of more than one `\p{Zs}` and any `\p{Zs}` other than U+0020. Apply `PADDED` to every top-level string, not just beneficiary values.
3. Define reserved beneficiary keys (`iban`, `account`, `bic`) restricted to `[A-Z0-9]` (IBAN with mod-97 check), and refuse mixed-script values in `name` (UTS #39 single-script or Latin+Common), or at least flag them to the bank.
4. Mirror the rules in both SDKs (they re-verify the signed bytes).

**Regression tests.** Add invalid vectors to `test-vectors/signed-payload-v1.json` (homoglyph mixed-script name, NFD value, double NBSP, full-width IBAN digit, padded `transaction_reference`) and extend `test/property-fuzz.test.mjs` to assert rejection.

### A1-03 (Medium) — No customer decline, and no bank cancel of a pending authorization

**What the code does.** The mobile router (`mobileV1.ts`) offers: GET authorization, verification plan, escalate, open session, call signalling, `cancel` of a **call** (`mobileV1.ts:327-333`, "nothing is verified or failed"), push registration, signature, deferred signature. The bank router (`nexusV1.ts`) has no cancel either. `CANCELLED` is reached only through credential revocation (`credentialService.ts:179-180`), device replacement (`credentialService.ts:104`) or identity suspension/revocation (`nexusIdentityService.ts:103,118`). `transitionTerminal` supports `REJECTED` (`authorizationConfirmation.ts:288,304-309`), but nothing calls it with that state (see A1-14).

**Why it matters.** A customer who receives a push for a payment they did not start can only ignore it. The bank learns nothing until `authorization.expired` (up to 900 s), and the expiry carries no fraud signal. That is the most valuable fraud indicator the product could give the bank, and it is missing. For the bank, an authorization it wants to withdraw (order changed, fraud system hit) stays signable until expiry. The bank can still refuse to commit, which limits the impact.

**Minimal fix.** Add `POST /v1/mobile/authorizations/:id/decline` (device-signed, add it to `DEVICE_ROUTES`, `deviceInScope` + `authorizationInScope`, body `{reason: 'NOT_ME'|'WRONG_DETAILS'|'OTHER'}`). It calls `transitionTerminal(id, clientId, 'REJECTED', ...)` with a `reason`, records an audit event and webhook `authorization.declined` with the reason, and optionally seals a DECLINED evidence record. Add bank `POST /v1/authorizations/:id/cancel`, moving PENDING_USER → CANCELLED under the row lock (the trigger already permits it, `schema.sql:452`).

**Regression test.** Integration: create, decline from the device, then assert state `REJECTED`, webhook enqueued, and that a later valid signature returns `FAILED` and `requestCommit` returns 409.

### A1-04 (Medium) — Identity creation is not retry-safe

**What the code does.** `createNexusIdentity` (`nexusIdentityService.ts:40-56`) throws `DuplicateBankCustomerError` when a non-revoked identity exists for `(client_id, bank_customer_ref)` (`:60-64`, index `schema.sql:45-47`). The route maps it to 409 with message only (`errorHandler.ts:25`). No `nexusId` is returned. No endpoint looks up an identity by `bankCustomerRef`: `GET /v1/nexus-identities/:nexusId` needs the ID.

**Scenario.** The bank calls `POST /v1/nexus-identities`, the identity commits, and the response is lost (timeout at the gateway). The retry gets 409 without the ID. The bank cannot learn the NEXUS ID and cannot create a new one for that customer. Only an operator revoke (admin approval, `adminApprovalService.ts:105`) frees the reference. Bank integrations hit this routinely.

**Minimal fix.** In `createNexusIdentity`, when the existing non-revoked row belongs to the same client and ref, return it with `replayed: true` (HTTP 200). This is safe because the ref is already scoped to the caller. Alternatively honour `Idempotency-Key` as `POST /v1/authorizations` does, or add `GET /v1/nexus-identities?bankCustomerRef=`.

**Regression test.** Integration: create twice with the same ref → same `nexusId`, second call 200. Another client with the same ref → independent identity.

### A1-05 (Low) — High-S ECDSA signatures accepted

**What the code does.** `SoftwareHsmAdapter.verifySignature` passes the signature to OpenSSL (`softwareHsmAdapter.ts:13-14`). The PKCS#11 path converts strict DER to raw (`pkcs11HsmAdapter.ts:112`) and lets the token verify. Neither enforces `s ≤ n/2`. Executed: for a valid raw signature `(r,s)`, `(r, n−s)` → `verifySignature(..., 'raw')` = `true`. Non-minimal DER is correctly refused (executed: `derToRaw` throws, software verify false).

**Impact.** Consumption is keyed on the authorization row state, not on the signature, so this gives no replay. But `submitDeferredSignature` (`authorizationConfirmation.ts:535-536`) compares stored and resubmitted signatures byte-wise. A malleated copy of the same device signature (e.g. a proxy re-encoding it) gets a 409 "different signature" instead of `ALREADY_RECORDED`. Evidence also stores one of two equally valid encodings. The doc's statement "Other encodings of the same values are refused" (`authorization-protocol-v1.md`, §Signature) is not true for `s`.

**Fix.** In `verifySignature` (both adapters), and in `authorizationEvidenceCheck.ts:94-99`, either reject `s > n/2` (iOS/Android produce either, so normalise on the device first) or normalise to low-S before storing and comparing. Document the choice.

**Test.** Unit: `(r, n−s)` → refused or normalised. Vector added to `signed-payload-v1.json` invalid set.

### A1-06 (Low) — Idempotency comparison incomplete

`findIdempotentReplay` (`authorizationService.ts:148-158`) compares nexus, credential, reference, type, amount, currency, beneficiary and policy, but not `expiresInSeconds`, `verificationPolicy` (e.g. `requireVideo`, `highAmountThresholdMinor`) or `pushNotification`. A retry with the same key but a stricter verification policy silently returns the weaker original. Fix: store a `request_hash = hashCanonicalJson(parsedBody)` at insert and compare it on replay. Test: same key, `requireVideo: true` on replay → 409.

### A1-07 (Low, Suspected) — Lock-order inversion

`revokeCredentialForClient` updates `credentials` (row lock) and then `authorization_requests` (`credentialService.ts:170-180`). `transitionTerminal` locks the plan, then `authorization_requests FOR UPDATE`, then `credentials FOR SHARE` (`authorizationConfirmation.ts:291-293, 332-333`). Run concurrently on the same pair, these can deadlock. Postgres aborts one side; the outcome is a 500 to the bank or the device. That fails closed, but it is an unexpected error in exactly the "revoke during in-flight confirmation" case. `nexusIdentityService.ts:113-121` has the same order. To confirm: run a concurrent revoke and signature loop against Postgres and look for `40P01`. Fix: in the revoke path, `SELECT ... FROM authorization_requests WHERE credential_id=$1 AND state='PENDING_USER' FOR UPDATE` before updating `credentials`, or take the credential lock first in `transitionTerminal`.

### A1-08 (Low) — `withTransaction` on ROLLBACK failure

```ts
// pool.ts:25-29
} catch (error) {
  await client.query('ROLLBACK');   // if this throws, `error` is lost
  throw error;
} finally { client.release(); }     // released without the error → broken socket returns to the pool
```

Fix: `try { await client.query('ROLLBACK') } catch (e) { client.release(e); released = true; } throw error;`, i.e. pass the error to `release(err)` so pg destroys the client. Test: a stub client whose ROLLBACK rejects; assert the original error propagates and `release` gets an error argument.

### A1-09 (Low) — Unscoped bank tokens

`issueToken` stores only `clientId` (`tokenService.ts:28`). The same token can create authorizations, relay offline codes, complete verification sessions (`nexusV1.ts:280`), send push messages and drive commit results. A token leaked from a peripheral bank system (e.g. the notification service) can therefore relay offline codes or finalize verification sessions. Fix: add `scope` to the stored value and to `/oauth/token` (`authorizations`, `verification-gateway`, `push`, `commit`), and check it in route-level middleware.

### A1-10 (Low) — No API rate limiting

Throttles exist only for `/oauth/token` and push receipts (`oauth.ts:20-26`, `mobileV1.ts:46-52`). Bank APIs and device-signed APIs (e.g. GET signals long-poll with `waitMs` up to 20 s, `mobileV1.ts:322`) have none. A compromised device key or bank token can exhaust the DB pool. Fix: per-client and per-credential token buckets in Redis, failing closed.

### A1-11 (Info) — Error semantics

Signature or offline-code failure returns HTTP 200 with `{status:'FAILED', reason, attempts}` (`nexusV1.ts:219,240`, `mobileV1.ts:368`). Deferred-signature failure returns 422/409 (`authorizationConfirmation.ts:571-573`). A bank integrator that checks only HTTP status treats a failed confirmation as success. Recommend 422 for FAILED, or at least document it prominently.

### A1-12 (Info) — Over-exposure on bank GET

`res.json({ ...auth, ...})` (`nexusV1.ts:199-201`) returns `signature`, `signatureFormat`, `nonce`, `offlineUnsignedReason` and similar. Not cross-tenant; prefer an explicit view.

### A1-13 (Info) — No tenant field in signed bytes

`AuthorizationObject` (`canonicalAuthorization.ts:6-22`) has no `client_id`. Cross-bank replay is still impossible: `authorization_id` is a server-generated UUID scoped by `client_id` in every lookup (`authorizationRecord.ts:67`), `nexus_id` is globally unique and owned by one client (`schema.sql:26`), and the signature covers both. Adding the bank identifier to a v2 object would make evidence self-describing for a third-party verifier.

### A1-14 (Info) — Engineering quality

- `authorizationConfirmation.ts:288,304-309`: `transitionTerminal` accepts `'REJECTED'` and has a branch for it, but the only callers pass `'EXPIRED'` (`:124`) and `'VERIFIED'` (`:173`). Dead code (and the natural home for A1-03).
- `authorizationConfirmation.ts:76`: orphan JSDoc "QR content for offline confirmation…" sits on top of `offlineLimitExceeded`'s doc. The real doc for `getOfflineChallenge` (`:96`) is missing.
- `nexusV1.ts:280`: `requireGatewayMtls` repeated on `/complete` though it already runs globally (`app.ts:93`). Harmless, but misleading about where the gate lives.
- `errorHandler.ts:18,49`: `CredentialIntegrityError` returns its message to the caller (`Credential integrity check failed: the credential keys differ from the sealed enrolment`). This tells an attacker with DB write access which check caught them. Return a fixed message; the reason is already audited (`credentialIntegrity.ts:68`).
- `authorizationService.ts:59-60` re-validates amount and currency already validated by zod (`nexusV1.ts:32-33`). Acceptable defence in depth, but the regex is duplicated in three places (also `parseOfflineLimits`). Export one constant.
- `mobileSessionService.ts:64-73`: `consumeMobileSession` does not re-apply the `clientId`/`nexusId` shape checks of `resolveMobileSession` (`:53`). The caller ignores the consumed value, so this has no impact.
- `credentialService.ts:17`: `CredentialState = 'ACTIVE' | 'REVOKED'`. There is no SUSPENDED credential state (relevant to question (c)).
- Double blank lines and `credentialService.ts:210-211` comment typo ("mobile request request authentication").
- `server.ts:47-49`: an `unhandledRejection` is logged and swallowed. That is acceptable for availability, but the process keeps running in an unknown state.
- `offlineCodeFromTag` (`deviceProtocol.ts:62-66`): 31-bit value mod 10^8 gives a ~1/21 relative bias on the low codes. Negligible with 5 attempts. Noted, no action.
- No TODO/FIXME found in the files in scope.

## 4. Security properties verified as correctly implemented

| Property | Implemented at | Covering test |
|---|---|---|
| NEXUS ID from CSPRNG, uniform (`crypto.randomInt` rejection sampling), range 100000000–999999999, no leading zero | `src/services/nexusIdentityService.ts:33` | none found in unit tests |
| NEXUS ID uniqueness: PK + `CHECK ^[0-9]{9}$`, retry on `nexus_identities_pkey` 23505, one non-revoked identity per (client, customer ref) | `schema.sql:26,45-47`; `nexusIdentityService.ts:45-55,60-64` | integration (not runnable here) |
| NEXUS ID alone authorizes nothing: bootstrap needs a bank token + identity ACTIVE; signing needs the bound credential's key | `mobileV1.ts:102-122`; `authorizationConfirmation.ts:128-150` | `test/mobile-session.test.mjs` (env-blocked) |
| NEXUS ID vs credential ID never confused: distinct formats (9 digits vs UUID) validated at every route | `nexusV1.ts:24-25`; `mobileAuth.ts:29,89` | — |
| Cross-bank identity access returns 404, the same as nonexistent (no enumeration) | `nexusIdentityService.ts:80-89`; `credentialService.ts:156-166`; `authorizationRecord.ts:66-71`; `evidenceService.ts:341-343,322-327` | integration |
| Private keys never reach the server: bootstrap accepts only public PEMs | `mobileV1.ts:26-35` | — |
| Public key validation: strict single PEM, EC prime256v1, uncompressed 65-byte SPKI (OpenSSL import refuses off-curve points) | `src/crypto/p256PublicKey.ts:20-45` | `test/crypto.test.mjs` |
| Signing/auth/offline keys must be distinct | `deviceKeysService.ts:36-39` | `test/device-protocol.test.mjs` |
| Attestation binds challenge + all enrolled keys; challenge derived from the single-use bootstrap token; platform cross-check; production requires verified attestation | `attestationBinding.ts:15-22`; `mobileSessionService.ts:41`; `mobileV1.ts:198-209`; `productionPosture.ts:17` | `test/device-attestation-policy.test.mjs` |
| Bootstrap token single use (Redis GETDEL) | `mobileSessionService.ts:64-66`; `mobileV1.ts:212` | `test/mobile-session.test.mjs` (env-blocked) |
| One ACTIVE credential per identity; replacement only with the bank's re-identification record; old credential revoked and its PENDING authorizations cancelled in the same tx | `schema.sql:626`; `credentialService.ts:82-107` | integration |
| Credential keys checked against the HSM-sealed enrolment record before every use | `credentialIntegrity.ts:66-101`; `authorizationConfirmation.ts:138-144`; `mobileAuth.ts:107` | `test/evidence.test.mjs` |
| Canonical encoding: recursive sorted keys, restricted beneficiary keys, Cc/Cf/Zl/Zp/Cs refused, integer-string amount ≤30 digits stored as `NUMERIC(30,0)`, no floats, UTC ms timestamps; 15 fields match the doc | `canonicalAuthorization.ts:30-101`; `schema.sql:84` | `npm run test:vectors` (45 vectors) ; `test/property-fuzz.test.mjs` |
| Signed terms immutable in DB; signed bytes re-derived and compared under lock before consumption | `schema.sql:432-450`; `authorizationConfirmation.ts:340-344` | `test/regression-2.0.test.mjs` |
| Validity window: TTL clamped 30–900 s; expiry checked before and under lock | `authorizationService.ts:74`; `authorizationConfirmation.ts:123,327-330` | integration |
| Algorithm fixed (ES256 / P-256 SHA-256); DER strictly minimal; raw must be 64 bytes; malformed input = counted failure; PKCS#11 errors other than SIGNATURE_INVALID rethrown (fail closed) | `ecdsaSignatureFormat.ts:18-32`; `pkcs11HsmAdapter.ts:106-135`; `softwareHsmAdapter.ts:9-17`; `authorizationConfirmation.ts:645-649` | `test/crypto.test.mjs`; executed check (non-minimal DER refused) |
| Atomic single-use consumption: `FOR UPDATE` + `OPEN_STATES` recheck; trigger allows only legal transitions; a concurrent second confirmation gets "finalized concurrently" | `authorizationConfirmation.ts:292-297`; `schema.sql:452-458` | `test/integration/invariants.test.mjs` (not runnable) |
| Credential and identity state rechecked inside the consuming transaction (`FOR SHARE`); revocation cancels PENDING_USER authorizations | `authorizationConfirmation.ts:331-339`; `credentialService.ts:179-180`; `nexusIdentityService.ts:103,118` | integration |
| 5-attempt limit, serialized under row lock, shared by signatures and codes | `authorizationConfirmation.ts:184-266` | integration |
| Offline: code = HMAC(K, domain‖0‖SHA-256(bytes)), K from ECDH+HKDF bound to credential, encrypted at rest, wiped after use; constant-time compare | `deviceProtocol.ts:48-66`; `deviceKeysService.ts:43-50`; `authorizationConfirmation.ts:215-226` | `test/device-protocol.test.mjs` + `device-protocols-v1.json` |
| Offline provisional never final: OFFLINE_PROVISIONAL is not open, webhook `confirmed:false`, commit requires VERIFIED (code + trigger), evidence check refuses code-only outside `immediate`, production forbids `immediate`, per-currency cap and per-credential daily ceiling under advisory lock | `authorizationRecord.ts:4-8`; `authorizationConfirmation.ts:353-375,458-465`; `bankTransactionService.ts:59`; `schema.sql:499-503`; `authorizationEvidenceCheck.ts:73-75`; `productionPosture.ts:42-50` | `test/integration/offline-*.test.mjs` (not runnable) |
| Deferred signature accepted only from the bound credential, only while awaited, verified against the enrolment key, finalizes under lock | `authorizationConfirmation.ts:511-570` | `test/integration/offline-deferred-signature.test.mjs` (mTLS off; see A1-01) |
| The bank's commit re-verifies the sealed evidence (HSM seal, chain link, terms, device signature) rather than trusting `state`; requires identity and credential ACTIVE and a fresh confirmation | `bankTransactionService.ts:70-88`; `authorizationEvidenceCheck.ts:40-101` | `test/evidence.test.mjs`; integration |
| Auth Core does not execute payments; commit is the bank's report | `bankTransactionService.ts:11-25,99-114` | — |
| Bank token bound to registered mTLS cert fingerprint; header accepted only from trusted proxy IPs | `tokenService.ts:47-54`; `oauth.ts:63-70`; `mtlsGateway.ts:53-79` | `test/gateway-and-webhooks.test.mjs` |
| OAuth: unknown/disabled client and wrong secret indistinguishable (dummy hash), per-IP throttle, no per-client lockout | `clientService.ts:53-67`; `oauth.ts:20-26` | — |
| Device request auth: ECDSA over method/path/timestamp/nonce/credential/body hash, ±skew, nonce in Postgres (PK) after signature check, identity status | `mobileAuth.ts:82-177` | `test/device-protocol.test.mjs`; `test/low-findings.test.mjs` (env-blocked) |
| Fails closed on Redis/DB outage: middleware errors → `next(error)` → 500; no catch turns an exception into acceptance (the only catches return `false`/refusal) | `auth.ts:40-44`; `mobileAuth.ts:76-79,120-125`; `bruteForceProtection.ts:44-46`; `errorHandler.ts:61-62` | `test/error-handler.test.mjs` |
| Mobile scope: authorization must belong to the session's client and NEXUS ID | `mobileV1.ts:66-70` | — |

## 5. Feature status

| Item | Status | Where / note |
|---|---|---|
| 1. NEXUS ID generation, uniqueness, bank-customer binding | IMPLEMENTED | `nexusIdentityService.ts:31-78`, `schema.sql:26,45` |
| 1. NEXUS ID retry / re-registration behaviour | PARTIAL | not retry-safe (A1-04); re-registration after REVOKED works |
| 1. Enumeration / PII | IMPLEMENTED | 404 parity across tenants; only `bankCustomerRef` returned, to the owning bank |
| 2. Credential registration, key validation | IMPLEMENTED | `p256PublicKey.ts`, `credentialService.ts:79-154` |
| 2. Attestation binding | IMPLEMENTED (parsers UNVERIFIED) | binding verified; App Attest / Key Attestation / Play Integrity parsers not audited |
| 2. Lifecycle states | PARTIAL | credential ACTIVE/REVOKED only (no SUSPENDED); identity ACTIVE/SUSPENDED/REVOKED |
| 2. Multiple devices | MISSING (by design) | one ACTIVE credential per identity, `schema.sql:626` |
| 2. Revocation affects in-flight authorizations | IMPLEMENTED | `authorizationConfirmation.ts:331-339`; possible deadlock A1-07 |
| 3. Transaction binding (all directive fields) | IMPLEMENTED | 15-field object; payee account reference only as free-form beneficiary entries; no tenant field (A1-13) |
| 3. Unicode / homoglyph handling | PARTIAL | control/format chars refused; no NFC, confusables, spacing (A1-02) |
| 3. Amount / overflow / ordering / duplicates | IMPLEMENTED | string integer, NUMERIC(30,0), sorted keys; SDK strict re-parse per doc |
| 4. Signature verification | IMPLEMENTED | high-S accepted (A1-05) |
| 4. Atomic single use, nonce store, fail closed | IMPLEMENTED | — |
| 5. Offline QR + code, provisional never final | IMPLEMENTED | — |
| 5. Offline v2 deferred signature in production | PARTIAL | blocked by mTLS gate (A1-01) |
| 6. Tenant isolation of queries | IMPLEMENTED | every lookup in scope filters by `client_id` or follows a scoped lookup |
| 6. Token audience/scope | MISSING | A1-09 |
| 6. OAuth client credentials + mTLS binding | IMPLEMENTED | — |
| 7. Zod validation on in-scope routes | IMPLEMENTED | `verification-sessions/:id/signals` POST `type: z.string()` unbounded but body limit 32 kB |
| 7. Rate limiting | PARTIAL | A1-10 |
| 7. Idempotency | PARTIAL | authorizations only, incomplete comparison (A1-06); identities none (A1-04) |
| (a) Recurring-payment mandates | MISSING | no code path; `operation_type` free text only |
| (b) Device list endpoint for a customer | MISSING | only `GET /v1/credentials/:credentialId` (`nexusV1.ts:140`); no list by NEXUS ID, nothing customer-facing |
| (c) NEXUS ID suspension by customer | MISSING | — |
| (c) NEXUS ID suspension by bank (API) | MISSING | operator-only: `routes/admin.ts:209` → `suspendNexusIdentity`; revoke/reactivate via admin approval `adminApprovalService.ts:105-106` |
| (d) Customer "reject / it wasn't me" | MISSING | A1-03; only call cancel (`mobileV1.ts:327`), which verifies or fails nothing |
