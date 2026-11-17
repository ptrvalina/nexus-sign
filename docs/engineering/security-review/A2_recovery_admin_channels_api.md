# A2 — Recovery, device lifecycle, admin, calls, push, webhooks, API contract, config

Auditor: independent read-only review. Repository: `nexus-sign` at HEAD `4eef752`. The two fixes made after the baseline (mTLS allow-list for deferred signature, display-text rules) are out of scope and are not reported.
All paths are relative to `auth-core/` unless stated otherwise. Line numbers refer to HEAD.

## Scope actually read

- Recovery: `src/routes/recovery.ts` (all), `src/services/recoveryService.ts` (all), `scripts/lib/recovery.mjs` (all), migrations 003, 006, 014, 015 (all). Docs: grep-level reading of `docs/protocol/recovery-protocol-v2.md`, `docs/architecture/device-replacement.md`, `docs/operations/runbooks/lost-or-stolen-device.md`, `recovery-lockout.md`.
- Device lifecycle: `src/routes/mobileV1.ts:102-130` (BOOTSTRAP/replacement), `src/services/credentialService.ts:40-110`, `src/services/nexusIdentityService.ts` (suspend/revoke/reactivate), `src/services/pushRegistrationService.ts:140-170`. SDK grep: `ios-sdk/.../KeyManager.swift`, `android-sdk/.../KeyManager.kt`, `RecoveryPhrase.swift`.
- Admin: `src/routes/admin.ts`, `src/middleware/adminAuth.ts`, `src/services/adminService.ts`, `adminAuthService.ts`, `adminApprovalService.ts`, `auditService.ts`, `src/crypto/password.ts`, `totp.ts`, `tokenDigest.ts`, `src/middleware/bruteForceProtection.ts`, `mtlsGateway.ts`, `auth.ts`, `src/services/requestContext.ts`, `public/admin/admin.js`, `calls.js`, `index.html` (structure), `src/cli/createAdminUser.ts`, migration 016 (all).
- Calls / adaptive verification: `src/services/adaptiveVerificationService.ts`, `verificationCall.ts`, `verificationResult.ts`, `src/crypto/jws.ts`, migrations 008, 019; `authorizationConfirmation.ts:280-300, 420-435` (plan gate); grep of `docs/operations/audio-video-calls.md`, ADR 0017.
- Push: `src/services/pushProtocol.ts` (all), `pushService.ts:1-140, 160, 322-345` and function index, `pushRegistrationService.ts:1-60, 95-105, 140-170`, `pushProviders.ts` header.
- Webhooks: `src/services/webhookService.ts`, `webhookUrlPolicy.ts`, `src/workers/webhookWorker.ts`, `clientService.ts` (webhook secret lines).
- API / errors: route list of all `src/routes/*.ts`, `openapi.yaml:848-935`, `docs/reference/error-responses.md` (grep), `src/middleware/errorHandler.ts`, `src/services/errors.ts`, `src/routes/oauth.ts`.
- Config: `src/app.ts`, `src/server.ts`, `src/config/env.ts`, `productionPosture.ts`, `.env.example`, `Dockerfile`, `docker-compose.yml` (grep).
- Not read: `apnsProviderToken.ts`, `googleServiceAccount.ts`, `workers/pushWorker.ts`, most of `pushProviders.ts`, migration 012, `docs/protocol/secure-push.md`, ADR 0008, ADR 0014 body. Statements about them are marked UNVERIFIED.

Execution: `npm run -s check:openapi` → `ok: 44 routes match openapi.yaml`. Unit tests passing: `admin-totp` (3), `secure-push` (12), `gateway-and-webhooks` (5), `crypto` (7), `production-posture` (16). `recovery-vectors` and `error-handler` fail only because `prom-client` / `pg` are not installed (environmental). One ad-hoc probe of `isPrivateIpv6` (A2-05) was run from the scratchpad, outside the repository.

## Findings

| ID | Severity | Title | Location | Status |
|---|---|---|---|---|
| A2-01 | High | Bank backend alone can move any NEXUS ID to a new device (device replacement needs no customer secret, no second person and no waiting period) | `src/routes/mobileV1.ts:110-126`, `src/services/credentialService.ts:93-106` | Confirmed |
| A2-02 | Medium | Recovery revokes the old device at once and silently: no security notice, no waiting period; the old recovery key stays valid | `src/services/recoveryService.ts:284-289, 316` | Confirmed |
| A2-03 | Medium | Platform (vendor) operators can answer and decide verification calls of every bank; a single operator's click satisfies an AUDIO/VIDEO requirement | `src/services/verificationCall.ts:138, 166`; `src/services/adaptiveVerificationService.ts:238-251` | Confirmed |
| A2-04 | Low | Identity-wide recovery failure limit is checked only when a session is opened; parallel sessions bypass "10 per identity per 24 h" | `src/services/recoveryService.ts:187-193, 260` | Confirmed |
| A2-05 | Low | Webhook SSRF filter misses IPv6 transition ranges (6to4, Teredo, local NAT64, discard) | `src/services/webhookUrlPolicy.ts:35-47` | Confirmed (executed) |
| A2-06 | Low | Anyone can lock a named admin out for 15 min, repeatably (per-username lockout from any address) | `src/routes/admin.ts:52` | Confirmed |
| A2-07 | Low | Reads of customer data in the console are partly unaudited; `admin_logout` is recorded with no actor | `src/routes/admin.ts:105, 133, 155, 242, 248` | Confirmed |
| A2-08 | Low | Webhooks: single secret with no rotation overlap, no redelivery after FAILED (~37 min of retries), events dropped silently when no destination is configured | `src/services/webhookService.ts:27, 35`; `src/services/clientService.ts:34-46, 85` | Confirmed |
| A2-09 | Low | Provider and TURN secrets stay plaintext in the environment even with `MASTER_KEY_SOURCE=hsm`; production posture does not check them | `src/config/env.ts:98, 157, 164, 215` | Confirmed |
| A2-10 | Low | Swallowed errors on security paths (integrity-violation audit write, operator bye, failed-login counter) | `src/services/recoveryService.ts:338`; `src/routes/admin.ts:92, 285` | Confirmed |
| A2-11 | Info | DTLS-SRTP is a claim, not a server-side control: SDP is relayed without inspection, so whoever controls Auth Core signalling can sit in the middle of the call | `src/services/verificationCall.ts:204-216`; `docs/operations/audio-video-calls.md:71` | Confirmed |
| A2-12 | Info | API contract gaps: 19 `/admin/api/*` routes have no specification; recovery completion has no 400 in the spec and a hand-written 401 | `openapi.yaml:882-930`; `src/routes/recovery.ts:47-51` | Confirmed (partial review) |

No Critical findings in this scope. A call outcome, a push or a push receipt cannot authorize a transaction without a device signature (see "Verified").

---

### A2-01 (High) Bank backend alone can take over any NEXUS ID through device replacement

**What the code does.** `POST /v1/mobile/sessions` (bank token + mTLS) accepts a self-declared replacement authorization:

```ts
// src/routes/mobileV1.ts:110-113
replacement: z.object({
  method: z.enum(['BRANCH_VISIT', 'VIDEO_IDENTIFICATION', 'IN_APP_STRONG_AUTHENTICATION', 'OTHER']),
  reference: z.string().min(1).max(128),
}).optional(),
```

It issues a BOOTSTRAP token. `createCredential` then revokes every active credential in the same transaction and enrols the new key:

```ts
// src/services/credentialService.ts:100-106
for (const credentialId of replacedCredentialIds) await queueReplacementNotice(...);
await client.query(`UPDATE credentials SET state = 'REVOKED', revoked_at = now() WHERE credential_id = ANY($1::uuid[])`, ...);
```

**Why this is a problem.** The recovery phrase design (`recoveryService.ts:32-37`, "Nothing stored by Auth Core lets anyone complete a recovery without the phrase") suggests the customer holds a secret that protects the identity. In practice, one authenticated bank call takes over any identity of that bank. Nothing in that path comes from the customer. `method` and `reference` are free text that Auth Core cannot check. There is no second person, no hold period, and nothing the old device has to sign. The only safeguards are an audit event (`mobileV1.ts:126`) and a best-effort push notice. That notice is sent only in push mode `NEXUS` (`device-replacement.md:75`). In mode `BANK`, which is the "Sign" package default (`clientService.ts:46`, `push_mode` default `'BANK'`), Auth Core sends nothing.

**Attack scenario.** An attacker steals a bank backend OAuth secret plus the gateway client certificate, or an insider has them. The attacker calls `/v1/mobile/sessions` with `replacement: {method:'OTHER', reference:'x'}`, enrols their own device and signs payments as the customer. All pending authorizations of the victim are cancelled, which hides the attack. The evidence chain shows a "valid" device signature.

**Minimal fix.** In `issueBootstrapToken`/`createCredential`, make replacement for an identity with an active credential a two-stage operation:
1. The bank requests a replacement, and Auth Core records it as `PENDING_REPLACEMENT` with a configurable hold, for example `DEVICE_REPLACEMENT_HOLD_HOURS`, default 24, with 0 allowed only when `method = IN_APP_STRONG_AUTHENTICATION` and a fresh signature by the old device is presented.
2. A notice goes to the old device in both push modes, through a `credential.replacement_requested` webhook in `BANK` mode.
3. The old device can cancel the request with a signed call.
4. Enrolment succeeds only after the hold.

Optionally, require a second bank client actor (four-eyes, mirroring `adminApprovalService`). Production posture should refuse a hold of 0.

**Regression test.** In `test/integration/device-replacement.test.mjs`: (a) a replacement BOOTSTRAP enrolment before the hold expires returns 409 `REPLACEMENT_ON_HOLD`, and the old credential stays ACTIVE; (b) a cancel signed by the old device during the hold makes later enrolment fail; (c) in push mode `BANK` a `credential.replacement_requested` webhook is enqueued.

### A2-02 (Medium) Recovery revokes the old device immediately, with no notice, and leaves the phrase valid

**What the code does.**

```ts
// src/services/recoveryService.ts:284-289
const oldCredentials = await tx.query(`SELECT credential_id,key_version FROM credentials WHERE nexus_id=$1 AND state = 'ACTIVE' FOR UPDATE`, ...);
if (revokedIds.length > 0) await tx.query(`UPDATE credentials SET state='REVOKED',revoked_at=now() WHERE credential_id = ANY($1::uuid[])`, [revokedIds]);
await tx.query(`UPDATE authorization_requests SET state='CANCELLED' WHERE nexus_id=$1 AND state='PENDING_USER'`, ...);
await forgetInactivePushRegistrations(tx, s.nexus_id);
```

Unlike device replacement (`credentialService.ts:102`), recovery never calls `queueReplacementNotice`. `forgetInactivePushRegistrations` (`pushRegistrationService.ts:145-157`) deletes the old device's registration in the same transaction, because no notice is queued to keep it. The only signal is the bank webhook `identity.recovered` (`recoveryService.ts:316`). The recovery key is not rotated after use. The runbook confirms this: "The recovery key configured on the old device stays on the identity" (`lost-or-stolen-device.md:123`).

**Why this is a problem.** Recovery is the path most likely to be abused with a phished phrase plus social engineering of the bank's re-identification. The real owner's phone loses its credential without warning. Because the same phrase still works afterwards, an attacker who has it can run recovery again after the owner recovers.

**Scenario.** A phrase is phished. The attacker gets through the bank call-centre re-identification, and the bank opens a recovery session. The attacker completes recovery. The victim's app starts getting 401s and no notice is shown. If the victim recovers back, the attacker can repeat the recovery.

**Minimal fix.** In `completeRecovery`, call `queueReplacementNotice(tx, s.client_id, s.nexus_id, id)` for each id in `revokedIds` before `forgetInactivePushRegistrations`, as `createCredential` does. Then clear the recovery configuration (`recovery_protocol=NULL`, key and wrapped key NULL, sealed as a `RECOVERY_CONFIGURED` record with a null key), so that the new device must set up a new phrase. Optionally apply the same hold as in A2-01.

**Regression test.** In `test/integration/recovery.test.mjs`: after `completeRecovery` in push mode NEXUS, one `push_messages` row with `replacement_notice = true` exists for the old credential. A second recovery session with the same phrase returns 409 `RECOVERY_NOT_CONFIGURED`.

### A2-03 (Medium) Platform operators can verify any bank's customer calls; one person decides

**What the code does.** An admin with `client_id IS NULL` (a platform operator, meaning Nexis staff: `createAdminUser.ts:374-375`) passes every bank filter:

```ts
// src/services/verificationCall.ts:138
if (operator.clientId !== null && operator.clientId !== row.client_id) throw new NotFoundError(...);
// src/services/verificationCall.ts:166
AND ($1::text IS NULL OR s.client_id = $1)
// src/services/adaptiveVerificationService.ts:242
if (!row || (operator.clientId !== null && operator.clientId !== row.client_id)) throw new NotFoundError(...);
```

`recordOperatorDecision` then marks the session VERIFIED, and the plan VERIFIED when the channel meets the requirement (`adaptiveVerificationService.ts:332-336`). This needs no second person and is not tied to any media actually having flowed.

**Why this is a problem.** The product model says the bank owns customer identification, and `docs/operations/audio-video-calls.md:41` says operators are "scoped to the bank". The code does not enforce that scope. A vendor employee can perform the bank's step-up check for a high-value payment, and the evidence then records an OPERATOR factor. The device signature is still required, so this cannot authorize a payment on its own. It does weaken the AUDIO/VIDEO requirement to "any console user of any bank or of the vendor clicked Verified".

**Minimal fix.** In `operatorCall`, `listCalls`, `claimCall` and `recordOperatorDecision`, require `operator.clientId === row.client_id` (refuse null). Optionally add a configurable four-eyes rule above an amount threshold.

**Regression test.** In `test/integration/verification-call.test.mjs`, a platform operator (`clientId: null`) gets 404 on `claim` and `decision`, and `listCalls` returns `[]` for it.

### A2-04 (Low) Identity-wide recovery failure limit is bypassable with parallel sessions

`createRecoverySession` counts failures only at session creation (`recoveryService.ts:187-193`). `completeRecovery` checks only the per-session limit, `if (s.attempt_count >= MAX_ATTEMPTS)` (`:260`). The bank backend can open N sessions while the failure count is still 0, which gives 5×N proofs. That contradicts "ten per identity in 24 hours" (`docs/reference/error-responses.md:137`). The impact is limited because the phrase has 128 bits of entropy (`ios-sdk/Sources/NEXUSSign/RecoveryPhrase.swift:21`), but the documented control is not what the code does.

**Fix:** in `completeRecovery`, after locking the identity row, repeat the `SUM(failed_attempt_count)` query and refuse with `RECOVERY_LOCKED`. Also mark other open sessions of the identity used when one completes.

**Test:** open 3 sessions, submit 4 bad proofs on each; the 11th attempt returns 409 `RECOVERY_LOCKED`.

Engineering note: the constant is interpolated into SQL, `interval '${RECOVERY_FAILURE_WINDOW}'` (`:189`). It is safe today, but a parameter (`$2::interval`) is better.

### A2-05 (Low) Webhook SSRF filter misses IPv6 transition prefixes

`isPrivateIpv6` (`webhookUrlPolicy.ts:35-47`) handles `::ffff:`, `64:ff9b::/96`, ULA, link-local, site-local, multicast and documentation. Executed probe results, all `false` (meaning allowed):

- `2002:a00:1::1` (6to4 → 10.0.0.1)
- `2002:7f00:1::` (6to4 → 127.0.0.1)
- `2001:0:4136:e378:8000:63bf:3fff:fdd2` (Teredo)
- `64:ff9b:1::a00:1` (local NAT64)
- `100::1` (discard)

The production allow-list (`WEBHOOK_ALLOWED_HOSTS`, required in production by `productionPosture.ts:62`) is a host-name list, not an address list. A DNS change for an allow-listed name can therefore still reach these ranges, where a relay or NAT64 exists.

**Fix:** refuse `2002::/16` when the embedded IPv4 is private, `2001::/32`, `64:ff9b:1::/48` and `100::/64`. Refusing all of `2002::/16` and `2001:0::/32` is simpler.

**Test:** add these addresses to the `IPv6 classification` test in `test/gateway-and-webhooks.test.mjs`.

### A2-06 (Low) Admin account lockout by strangers

The third throttle keys only on the body `username`: `{ keyPrefix: 'admin_login_failures_user', extractKey: byUsername, maxFailures: 50, windowSeconds: 3600, lockoutSeconds: 900 }` (`admin.ts:52`). `guard` refuses every request whose key is locked (`bruteForceProtection.ts:33-41`), including from the legitimate operator's own address. 50 requests from any set of addresses that reach the console lock an operator out for 15 minutes, repeatably. That could block four-eyes approvals or call handling during an incident. The console is behind the mTLS gateway in production (`app.ts:93`), so the attacker must be inside that perimeter.

**Fix:** when only the account-wide key is locked, keep accepting the login if a correct TOTP is presented, for example by checking the global key only after password and TOTP fail, or exempt source addresses that recently logged in successfully.

**Test:** 50 failures from IP A; a correct login from IP B with valid TOTP succeeds.

### A2-07 (Low) Incomplete audit of console reads; logout without actor

- `POST /admin/api/logout` runs before the session middleware, so `recordAuditEvent('admin_logout', {})` (`admin.ts:105`) writes `actor = NULL`. Fix: resolve the session before deleting it and pass `actor: admin:<username>`.
- `GET /admin/api/clients` (`:133`), `/webhook-deliveries` (`:155`, includes `lastError` and the bank event stream), `/verification-calls` (`:242`, returns `nexusId`, amount and beneficiary of every waiting call) and `claim` reads are not audited. Only `audit-logs` (`:148`) and `identities/:id` (`:175`) are. `auditService.ts:6-7` says "Every security-relevant state change must have a matching call"; reads of personal data in a bank context usually need the same.

**Test:** after each GET, `audit_logs` has one row with the event type and `actor`.

### A2-08 (Low) Webhook reliability and key rotation

- One secret per client (`clientService.ts:34-46`, `:85`). Rotating it breaks verification at the bank until both sides switch, because there is no overlap and no second `v1=` signature.
- `RETRY_DELAYS_SECONDS = [1, 5, 30, 300, 1800]` (`webhookService.ts:27`): about 37 minutes, then FAILED. No API or CLI redelivers. A bank outage longer than that loses `identity.recovered`, `credential.replaced`, `authorization.*` notifications, and the bank must poll.
- `enqueueWebhook` returns silently when no destination is configured (`:35`), so no record of the event exists for later delivery.

**Fix:** store `webhook_secret_previous` with an expiry and send `v1=<new>,v1=<old>` during overlap. Lengthen the schedule (hours to days) and add an admin "redeliver" action with audit.

**Test:** with previous and current secrets set, the signature header carries both HMACs.

### A2-09 (Low) Third-party credentials outside the master-key protection

`APNS_PRIVATE_KEY_PEM` (`env.ts:157`), `FCM_SERVICE_ACCOUNT_JSON` (`:164`), `GOOGLE_SERVICE_ACCOUNT_JSON` (`:215`) and `WEBRTC_TURN_SECRET` (`:98`) are read as plaintext environment values. `MASTER_KEY_SOURCE=hsm` covers only the three master keys (`productionPosture.ts:158`). An APNs key lets its holder push to every installation of the bank app. That is a phishing channel even though push is not consent.

**Fix:** support `_WRAPPED` variants through `masterKeyVault`, or document a secret-manager requirement and check for it in `productionBlockers`.

### A2-10 (Low) Swallowed errors on security paths

- `recoveryService.ts:338`: `await recordAuditEvent('integrity_violation', ...).catch(() => undefined);`. A tampering signal is lost if the audit insert fails, with no log line.
- `admin.ts:285`: `await sendBye(...).catch(() => undefined);` after a decision.
- `admin.ts:92`: `await throttle.recordFailure(req).catch(() => undefined);`. If Redis is failing, brute-force counting silently stops.

**Fix:** log at `error` level with the request logger, and for the throttle fail closed (answer 503).

### A2-11 (Info) DTLS-SRTP is asserted, not enforced

`validateSignal` (`verificationCall.ts:204-216`) checks only the type and the SDP length. Auth Core relays SDP, including `a=fingerprint`, unchanged. Browsers and WebRTC stacks always use DTLS-SRTP, so encryption in transit is real. Authenticity of the peer, however, rests entirely on Auth Core and the admin session: whoever can write signals (a compromised Auth Core or Redis) can substitute fingerprints and relay media. `audio-video-calls.md:71` says "fingerprints exchanged through the authenticated signalling", which is accurate but should state this trust assumption. No code shows the operator anything that binds the call to the customer beyond the transaction terms.

**Fix (optional):** show a short authentication string derived from both DTLS fingerprints on the phone and in the console (`calls.js`), and have the operator read it out.

### A2-12 (Info) API contract gaps

- `check:openapi` reports 44 matching routes, which is all public routes: 21 mobile, 19 bank (`nexusV1.ts`), 2 recovery, 1 oauth, plus 1 counted elsewhere. The 19 `/admin/api/*` routes in `admin.ts` are not specified anywhere, so the console API has no contract or schema tests.
- `POST /v1/recovery/sessions/{id}/complete` (`openapi.yaml:882-930`) lists 200/401/403/404/409. The handler also returns 400 (`ZodError`, `errorHandler.ts:38-43`) and can return 410 from `GoneError` paths. The 401 for a missing token is hand-written (`recovery.ts:49`) instead of `throw new UnauthorizedError(...)`, which duplicates error-shaping logic.
- Error bodies differ by design: `{error}`, `{error, code}`, OAuth `{error, error_description}`, throttle `{error:'too_many_attempts', retryAfterSeconds}`, device clock `{error, serverTime}`. This is documented consistently in `docs/reference/error-responses.md:13-31` and matches `errorHandler.ts`, so it is not a defect.
- A full schema-by-schema drift check of all 44 operations was not done in this pass (could-not-verify).

---

## Security properties verified as correctly implemented

| Property | Evidence | Covering test |
|---|---|---|
| Recovery needs the phrase: the proof is an ECDSA signature by the recovery key, which is stored only wrapped under PBKDF2(210k)+HKDF; the server never sees the phrase; the proof binds session, nonce, NEXUS ID and the new key's SPKI | `recoveryService.ts:39, 90-92, 274-276`; `scripts/lib/recovery.mjs:9-55` | `test/recovery-vectors.test.mjs` (environmental fail), `test/integration/recovery.test.mjs` (not runnable) |
| Bearer token alone is insufficient; the token is 256-bit, stored as SHA-256, compared in constant time, 10-min TTL, single use (`used_at` set in the same transaction) | `recoveryService.ts:199-207, 228-230, 257-259, 312` | — |
| The recovery key is checked against the sealed, latest `RECOVERY_CONFIGURED` evidence (no DB substitution or rollback) | `recoveryService.ts:333-358` | — |
| Old credentials are revoked, pending authorizations cancelled and the new credential sealed atomically in one transaction; a failed proof is committed as a counted attempt | `recoveryService.ts:252-321` | — |
| Recovery is refused for non-ACTIVE identities or a disabled bank client; it cannot cross banks (session `client_id` = identity `client_id`) | `recoveryService.ts:180, 261-266` | — |
| Recovery setup requires the device signing-key signature and a single-use salt | `recoveryService.ts:121-137` | — |
| Admin password: scrypt N=2^17,r=8,p=1, 16-byte salt, constant-time compare, dummy work for unknown users, upgrade on login, minimum length 12 | `password.ts:20-80`; `adminAuthService.ts:27, 52-57, 99-100, 119-120` | `test/crypto.test.mjs` |
| TOTP: RFC 6238, ±1 step, constant-time, replay blocked by a monotonic `totp_last_step` updated atomically | `totp.ts:52-62`; `adminAuthService.ts:104-113` | `test/admin-totp.test.mjs` (3 pass) |
| MFA required by default; a production blocker if disabled | `env.ts:261`; `productionPosture.ts:38` | `test/production-posture.test.mjs` (16 pass) |
| Sessions: 256-bit random, hashed in Redis, 30-min idle and 8-h absolute, account re-checked per request, invalidated by `session_version` | `adminAuthService.ts:122-150` | — |
| Cookie `HttpOnly; SameSite=Strict; Path=/admin; Secure` (Secure required in production); CSRF via Origin check on all `/admin/api` non-GET requests | `admin.ts:57-77, 81`; `productionPosture.ts:35-37` | — |
| Every `/admin/api` route except login/logout requires a session; all state changes require `operator`; bank scope applied in every listing | `admin.ts:115-118, 192, 204, 226, 242-279`; `adminService.ts:41-44, 98-101, 151-156` | `test/integration/admin-audit-mtls.test.mjs` (not runnable) |
| Four-eyes for REVOKE/REACTIVATE: the requester cannot approve (application check plus DB CHECK `decided_by <> requested_by`), one pending request per identity/action, executed in the approval transaction, audited | `adminApprovalService.ts:103-115`; migration `016:52, 55-57` | — |
| Audit log is append-only (UPDATE/DELETE/TRUNCATE triggers); actor, IP and bank are attached from the request context | migration `016:20-28`; `auditService.ts:27-51` | — |
| Console XSS: every server value is passed through `escapeHtml` before `innerHTML`; badge classes are regex-restricted; no inline script (helmet default CSP `script-src 'self'` applies) | `admin.js:47-58, 66-76`; `calls.js:28, 39-43, 96-99`; `app.ts:47`; `index.html:200-201` | — |
| No admin endpoint is reachable without auth; static `/admin` serves only public files; production requires the mTLS gateway for `/admin` | `app.ts:93, 113-114`; `mtlsGateway.ts:16-34` | `test/gateway-and-webhooks.test.mjs` |
| A call outcome cannot authorize: `recordOperatorDecision`/`completeVerificationSession` only change the plan; `state='VERIFIED'` is set only in `authorizationConfirmation.ts:387` after signature verification, and the plan is a precondition there (`:291`, `:427`) | `adaptiveVerificationService.ts:299-340, 367-375` | `test/integration/verification-results.test.mjs` (not runnable) |
| Provider results: ES256 only, no `jwk/jku/x5c/x5u/crit`, key chosen from the registry by (bank, iss, kid), bound to aud/sub/authorization/payload hash/credential/channel/nonce, max 600 s lifetime, single-use `jti` (unique index) | `jws.ts:21-61`; `verificationResult.ts:58-118`; `adaptiveVerificationService.ts:205-214`; migration `019:35-36` | — |
| Plan never downgrades; replay of the authorization cannot weaken it; session attempts are limited to 3 per channel | `adaptiveVerificationService.ts:100-106, 128, 155-159` | — |
| Signalling state machine atomic in Redis (Lua); only the device offers, only the claiming operator answers; inbox caps; TURN REST credentials scoped to the session with a ≤ TTL expiry | `verificationCall.ts:224-263` (Lua script), `:113-122` (TURN) | `test/media/webrtc-call.test.mjs` (UNVERIFIED run) |
| Push is not consent: `AUTHORIZATION_REQUEST` carries only `authorizationId`; a receipt moves the message to DELIVERED only; the PUSH-level plan is settled inside the signature-confirmation transaction | `pushProtocol.ts:67-68`; `pushService.ts:322-345`; `adaptiveVerificationService.ts:367-373` | `test/secure-push.test.mjs` (12 pass) |
| Push envelope: per-device key from ECDH P-256 + HKDF-SHA256 (salt = domain, info = credentialId); AES-256-GCM, random 96-bit IV per message, AAD binds messageId+credentialId; key stored under the device master key with an owner AAD; receipt is HMAC under the push key, constant-time compared; content filtered for bidi/format characters | `pushProtocol.ts:83-151`; `pushRegistrationService.ts:98-102` | `test/secure-push.test.mjs` |
| Webhook HMAC-SHA256 over `"<timestamp>.<raw body>"`, event-id header, sent body equals signed body; delivery pinned to the vetted IP (no DNS rebinding), no redirects followed, 10 s timeout, lease-based claiming with `SKIP LOCKED` | `webhookService.ts:42-44, 60-87, 112-165`; `webhookUrlPolicy.ts:62-86` | `test/gateway-and-webhooks.test.mjs` (5 pass) |
| Production posture: software HSM, missing attestation, plaintext master keys, Redis nonce store, insecure cookie, MFA off, missing mTLS/allow-list/TLS all block startup; development deviations need `ALLOW_INSECURE_DEVELOPMENT=true`; `NODE_ENV` has no default; Docker runtime is non-root with `NODE_ENV=production` | `productionPosture.ts:7-67, 70-79, 135-144`; `env.ts:11-19`; `Dockerfile:17, 34-35` | `test/production-posture.test.mjs` |
| No default secrets ship: `.env.example` master keys are empty; `docker-compose.yml` credentials (`nexus/nexus`) are local-only and bound to loopback | `.env.example:37-41`; `docker-compose.yml:1, 7-8` | — |

Not verified here: webhook receiver-side replay window (receiver's responsibility; Auth Core only supplies the timestamp); APNs JWT and Google token caching and expiry (`apnsProviderToken.ts`, `googleServiceAccount.ts` not read).

## Feature status

Recovery and device lifecycle
- Recovery with phrase (protocol 2, BIP39-style 128-bit, PBKDF2 + wrapped P-256 key): IMPLEMENTED
- Bank re-identification before recovery: PARTIAL (the bank opens the session; Auth Core records nothing about how the customer was re-identified)
- Recovery rate limits / lockout: PARTIAL (A2-04)
- Old-device notice on recovery: MISSING (A2-02)
- Device replacement with bank authorization: IMPLEMENTED (weak control, A2-01)
- Replacement notice to old device: PARTIAL (push mode NEXUS only)
- New-device approval by the old device: MISSING
- Lost/stolen device: PARTIAL (bank `POST /v1/credentials/{id}/revoke`, admin suspend/revoke; no customer-initiated path)
- Identity suspension / reactivation (four-eyes) / revocation (four-eyes): IMPLEMENTED
- Per-device suspension (as opposed to per identity): MISSING
- Device list or management: MISSING
- Biometric-change invalidation: PARTIAL (SDK-side only: `.biometryCurrentSet`, `setInvalidatedByBiometricEnrollment(true)` in the SDK `KeyManager`s; the server has no event or state for it)

Admin console (`public/admin`)
- Login with password + TOTP, sessions, roles, bank scoping: IMPLEMENTED
- Four-eyes approvals UI: IMPLEMENTED
- Audit log viewer: IMPLEMENTED
- Webhook deliveries viewer: IMPLEMENTED
- Identity lookup and suspend/revoke/reactivate: IMPLEMENTED
- Verification call answering: IMPLEMENTED
- Dashboard counts (identities, authorizations by state, webhooks): IMPLEMENTED
- Authorization / request list and detail: MISSING (counts only)
- Mandates: MISSING (no concept in code)
- Devices / credentials view: MISSING
- Confirmation status per transaction: MISSING (counts only)
- Risk review queue: MISSING
- Evidence access from console: MISSING (evidence is available only via the bank API `GET /v1/.../evidence`)
- Admin account management in UI: MISSING (CLI only, `createAdminUser.ts`)

Calls
- Signalling relay (offer/answer/candidates/bye, long poll): IMPLEMENTED
- TURN credentials (REST/HMAC): IMPLEMENTED
- Session authorization (device signature / claimed operator): IMPLEMENTED (vendor-operator scope issue A2-03)
- Provider-signed results: IMPLEMENTED
- DTLS-SRTP: UNVERIFIED as a server-side control (delegated to the WebRTC stacks, A2-11)
- Recording: MISSING (by decision, ADR 0017)

Push
- Auth Core-operated push via APNs/FCM (push mode NEXUS, "Full Pack"): IMPLEMENTED
- Bank-operated push (mode BANK, "Sign"): IMPLEMENTED as "Auth Core sends nothing"
- Envelope encryption and receipts: IMPLEMENTED
- Provider token handling: UNVERIFIED

Webhooks
- Signed delivery: IMPLEMENTED
- Retries: IMPLEMENTED
- SSRF policy: PARTIAL (A2-05)
- Secret rotation overlap: MISSING
- Redelivery: MISSING

Customer-facing / communication features (searched across `auth-core/src`, SDKs, console)
- In-app chat between bank and customer: MISSING
- Bot / assistant: MISSING
- Handover to an agent: MISSING (the only human contact is the AUDIO/VIDEO verification call bound to one authorization)
- Communication history: MISSING (push messages are stored per message for delivery status only; there is no customer-facing history API)
- Customer-facing settings for channels or limits: MISSING (channels and limits are bank policy or deployment configuration)
- Customer security log / event feed: MISSING (the audit log is admin-only; the bank gets webhooks)

## Items to record (from this audit, not from memory)
None beyond the findings above.
