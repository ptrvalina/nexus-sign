# Audit C: database layer and bank execution boundary (NEXUS-SIGN 2.0.0-rc.2)

Auditor scope: PostgreSQL schema, migrations and roles of Auth Core; the bank-side schema `bank` and the bank execution path in `bank-integration/`. Repository commit `5999984` (unmodified). Database: PostgreSQL 16.15 at 127.0.0.1:55432.

## 1. Scope read

- `auth-core/src/db/schema.sql`, `auth-core/migrations/002…022`, `migrations/README.md`, `scripts/db/roles.sql`, `src/db/pool.ts`, `src/db/redis.ts`
- `bank-integration/{schema,paymentGateway,executionBoundary,registry,trustStore,authCoreClient,webhookHandler,index}.mjs`, `README.md`
- `auth-core/scripts/lib/bankTrust.mjs`, `scripts/lib/evidence.mjs` (verifyEvidenceRecord, verifyDeviceSignature), `scripts/bank-execution-check.mjs`, `scripts/bank-trust-statement.mjs`
- `auth-core/src/services/bankTransactionService.ts`, `routes/nexusV1.ts` (commit routes), `middleware/mobileAuth.ts` (nonce store), `middleware/bruteForceProtection.ts`, `config/productionPosture.ts`, `crypto/secretBox.ts`, `crypto/selectHsmAdapter.ts`, `services/authorizationExpiry.ts`
- Tests (titles and claims; they cannot run here, no `pg` module): `state-machine.test.mjs`, `db-roles.test.mjs`, `bank-db-authorization.test.mjs`
- Docs: `docs/security/bank-database-authorization.md`, `docs/architecture/{bank-trust-boundary,payment-state-machine,state-machines}.md`, `docs/reference/data-model.md`, ADR 0013, `docs/operations/{disaster-recovery,upgrade-2.0}.md`, `docs/integration/pilot-execution-pack.md` (§10)

Not read in full: `webhookService.ts` (only its role as sender; the bank never trusts webhook content, see §5), the full 189-line upgrade-2.0.md.

## 2. Setup and reproducible scripts

All scripts are in `audit/tmp_C/` (run from that directory). Outputs are saved next to them (`*.out`).

| Script | What it does |
|---|---|
| `01_migrations.sh` | (a) 002…022 on an empty DB, (b) schema.sql only, (c) schema.sql + all migrations, (d) schema twice + migrations twice; sorted statement-level `pg_dump --schema-only` diffs |
| (inline, §C-06) | minimal pre-1.0 baseline (`bank_clients` only) + 002…022 into `audit_c_baseline`; `01b_baseline_vs_schema.diff`, `cols_*.txt` |
| `00_setup_core.sh`, `20_core_seed.sql` | `audit_c_core`: schema.sql + roles.sql, `nexus_app`/`nexus_owner` given LOGIN, two tenants seeded |
| `21_core_attacks_app.sql` | attacks as `nexus_app` (DDL, triggers, evidence/audit, lifecycle, GUC, tenants, nonces, shadowing, RLS) |
| `22_core_insert_bypass.sql` | INSERT of end states; TEMP privilege; trigger function properties |
| `23_core_owner.sql` | what `nexus_owner` can do |
| `24_race.sh` | two concurrent confirmations (two sessions, explicit transactions) |
| `gen_bank_sql.mjs` → `bank_install.sql` | SQL equivalent of `installSchema()` + `DATABASE_HARDENING` (roles `bank_owner`, `bank_boundary`, `bank_gateway`, `bank_registry`, `bank_ops`) into `audit_c_bank` |
| `10_bank_function_inventory.sql` | owner, SECURITY DEFINER, search_path, ACL of every `bank.*` function; TEMP/CREATE; RLS |
| `30_bank_attacks.sh` | registry/boundary/gateway attacks, forged evidence, replay, other payment, expired lease, GUC, owner |
| `31_bank_restore.sh` | backup taken at APPROVED, payment executed, restore, claim again |

Environment note: during the run the directory `<review host temp directory>` was reset to mode 0700 by the host, which made the PostgreSQL checkpointer PANIC (`could not open file …/pg/data/global/pg_control: Permission denied`, see `pg/log.txt`). I bind-mounted `…/scratchpad/work/pg` to `/srv/audit_pg` and restarted the same cluster from `/srv/audit_pg/data` on the same port (55432, trust auth). It is running.

## 3. Findings

| ID | Sev | Title | Location | Status |
|---|---|---|---|---|
| C-01 | High | A bank-DB restore (or any loss of the SUBMITTED record) sends an already executed payment again; the first submission never consults provider idempotency or lookup | `bank-integration/schema.mjs:375-406`, `executionBoundary.mjs:91-171`, `paymentGateway.mjs:275-292`; `auth-core/src/services/bankTransactionService.ts:60-65` | Confirmed (live DB) |
| C-02 | High | The database "execution permission" is not bound to a customer signature: the boundary role reaches APPROVED with self-made evidence and the gateway role gets the order from `bank.submit` without any cryptographic check; the only check is JS code in the gateway process | `schema.mjs:192-224, 414-442, 530-545`; `paymentGateway.mjs:236-273` | Confirmed (live DB) |
| C-03 | Medium | No time limit on execution inside the bank's zone: the signed `expires_at`/`issued_at` are never checked; Auth Core's max age applies only to the first commit request and is skipped on the idempotent replay | `bankTrust.mjs:107-124`, `schema.mjs:192-224`, `bankTransactionService.ts:60-65, 77` | Confirmed (DB accepted signed bytes with no expiry at all) + code reading |
| C-04 | Medium | Unverified registry statements do count in the DB: a forged approval squats a credential ID for another customer, a forged revocation is final; both permanently block genuine approvals (doc says they "count nowhere") | `schema.mjs:607-642`, `298-307`; `docs/security/bank-database-authorization.md:85` | Confirmed (live DB) |
| C-05 | Medium | Auth Core state machine is UPDATE-only: `nexus_app` INSERTs an authorization already `VERIFIED` (no signature, no `verified_at`) and `COMMITTED`; `bank_transaction_state` has no CHECK (any string) | `schema.sql:97-98, 109, 511-513` | Confirmed (live DB) |
| C-06 | Medium | Migration path cannot be verified: no 001/baseline in the repo; 002…022 fail on an empty DB; CI's "schema.sql then migrations" is a no-op; on a minimal baseline 7 migrations fail; schema.sql has columns no migration creates | `migrations/README.md:7,52`; `schema.sql:91-92, 133` vs `002:90` | Confirmed (live DB) |
| C-07 | Low | Audit-relevant fields remain writable after the final state; audit rows accept caller-supplied (back-dated) timestamp and actor | `schema.sql:106, 111-112, 231-245, 496-507` | Confirmed (live DB) |
| C-08 | Low | `secret_rewrap_allowed()` guard is a GUC any session can set: `nexus_app` replaces a credential's offline secret ciphertext (DoS; swap to another credential's ciphertext is defeated by AES-GCM AAD) | `schema.sql:519-535`; `crypto/secretBox.ts:80-96` | Confirmed (live DB) |
| C-09 | Low | Boundary role can push a customer's kept chain head to `2147483647` irreversibly (forward-only), so every later check against the kept head fails | `schema.mjs:333-346, 492-493`; `trustStore.mjs:211-214` | DB part confirmed; decision effect Suspected |
| C-10 | Low | No row-level security anywhere; tenant isolation is only in application `WHERE client_id = …`; `nexus_app` reads and rewrites every bank's rows, including `bank_clients.webhook_url`/`mtls_cert_sha256`, `admin_users`, `verification_providers` | `scripts/db/roles.sql:56-61` | Confirmed (live DB) |
| C-11 | Low | `nexus_app` may DELETE unexpired device nonces (grant not limited to expired rows, contrary to its comment) | `scripts/db/roles.sql:14-15, 59-60` | Confirmed (live DB) |
| C-12 | Low | Provider outcomes: no distinct "provider rejected"; a 4xx without a known status becomes OUTCOME_UNKNOWN; the reference HTTP provider has no authentication | `paymentGateway.mjs:212, 285-289, 388-403` | Code reading |
| C-13 | Low | REVIEW is settled by one operator; Auth Core is never told (no `commitResult`), so it stays `COMMIT_REQUESTED` | `schema.mjs:647-661`; `registry.mjs:42-47` | Code reading |
| C-14 | Low | Redis-only security state: login throttles/lockouts, admin and mobile sessions, bank tokens, recovery setup salts, call operator claims; a flush resets lockouts | `middleware/bruteForceProtection.ts:35-58`, `services/*` | Code reading |
| C-15 | Info | Auth Core trigger functions are not `SECURITY DEFINER` and have no pinned `search_path`; `nexus_app` keeps TEMP on the DB (shadowing attempt failed) | `schema.sql:213-702`; `roles.sql` (no `REVOKE TEMPORARY`) | Confirmed not exploitable |
| C-16 | Info | Owner/superuser can disable triggers and TRUNCATE `offline_deferred_signatures` (no TRUNCATE trigger) | `schema.sql:695-702` | Confirmed (live DB) |
| C-17 | Info | Model/naming: unused columns, duplicate state, stale ADR states, optional `operationType` leaves the signed operation type unchecked | see section | Code reading |
| C-18 | Info | Backup, restore, retention: no scripts; docs only, with placeholders | `docs/operations/disaster-recovery.md:9-10` | Code reading |

---

### C-01 (High) Restored bank journal re-sends an executed payment

**Code.** `bank.claim` decides between a fresh check and reconciliation only from the restored row:
```sql
-- schema.mjs:402-405
UPDATE bank.executions e SET state = CASE WHEN ex.state IN ('HELD', 'CHECKING') THEN 'CHECKING' ELSE 'RECONCILING' END, ...
```
A row restored as `APPROVED`/`CHECKING`/`HELD` (or a payment with no execution row) goes to `CHECKING` → `approve` → `gateway.submit` → `bank.submit` → `provider.submit(order)`. The first submission (`paymentGateway.mjs:275-280`) does not look at `providerCapabilities.idempotentSubmit` or `lookup`; those are used only in `reconcile()` (`executionBoundary.mjs:66-89`). Auth Core is no brake: `requestCommit` returns the current view (HTTP 202) for `COMMITTED` with the same reference (`bankTransactionService.ts:60-65`).

**Reproduction** (`31_bank_restore.sh`, output `31_bank_restore.out`):
```
approve -> t
-- backup taken while APPROVED          (pg_dump -Fc audit_c_bank)
bank.submit -> OP-5 ; bank.report(...,'succeeded') -> t
-- live journal:      EXECUTED|1
-- restored journal:  APPROVED|0        (pg_restore into audit_c_bank_restored)
-- after the restored approval lease has passed:
SELECT * FROM bank.claim(pay, 60000);  -> CHECKING | 5ec4533a-…
```
From `CHECKING` the normal path sends `OP-5` a second time (lease expiry was simulated by the superuser setting `lease_until` in the restored copy; with real time the 1 h lease simply runs out).

**Impact.** Every payment executed between the backup point and the failure is sent again after a restore, unless the provider deduplicates `operationId`. `docs/integration/pilot-execution-pack.md:177` promises "nothing is executed again". This is double payment.

**Fix.**
1. In `paymentGateway.send()` before the first `provider.submit`, when the provider declares `lookup`, call `provider.lookup(operationId)` and record the answer instead of sending if it is not `not_found`. Without `lookup` and without `idempotentSubmit`, refuse to start in production (`createExecutionBoundary`/`createPaymentGateway` throw unless both are true or an explicit `allowNonIdempotentProvider` is set).
2. Add a restore procedure to the bank schema: `bank.after_restore()` (owner) that moves every non-final execution to `RECONCILING` with `submissions = greatest(submissions,1)`, and marks `AWAITING_AUTHORIZATION` payments without an execution row as needing reconciliation (new state `RESTORED`), so that `claim` reconciles instead of checking.
3. Treat Auth Core's `bank_transaction_state = COMMITTED` (an untrusted but useful signal) as a reason to go to `REVIEW` instead of sending.

**Regression test.** Integration test: execute a payment, restore a dump taken at `APPROVED`, run `boundary.execute`; assert the provider double received exactly one `POST /payments` for that `operationId`.

### C-02 (High) The DB approval is forgeable; the cryptographic check exists only in gateway JS

**Code.** `bank.evidence_problem` checks shape and binding only; it recomputes `sha256(signedPayloadBase64)` (which the caller also computes) and compares terms. Device signature, HSM seal and the bank statement signatures are not checked (stated at `schema.mjs:189-191`). `bank.submit` (`schema.mjs:530-545`) checks state, attempt, lease and order hash, nothing about the evidence. The re-check is `bankExecutionDecision` in `paymentGateway.mjs:251`, i.e. in the gateway process, between `submit_basis` and `submit`.

**Reproduction** (`30_bank_attacks.sh`, `30_bank_attacks.out`), roles from `installSchema`:
```
-- registry: approval whose signature is the string 'NOT-A-SIGNATURE' -> stored
-- boundary: create_payment, claim, then approve with self-made evidence (no seal, no device signature):
SELECT * FROM bank.approve(pay, attempt, '<30_forged_evidence.json>'::jsonb, 3600000);
 ok | lost | reason
 t  | f    |
 state APPROVED, credential_id 33333333-…, order_hash bound
-- gateway role, raw SQL (any adapter that skips bankExecutionDecision):
SELECT * FROM bank.submit(pay, attempt);
 OP-1 | {"currency":"EUR","amountMinor":"1000","beneficiary":{"iban":"DE00"},"operationId":"OP-1",…}
SELECT bank.report(pay, attempt, 'succeeded','PROV-1',NULL);  -> t
transition log: CHECKING(claim) -> APPROVED(approve) -> SUBMITTED(submit) -> EXECUTED(report)
```
In this run the evidence was forged and the registry approval carried no valid signature, yet the database issued and consumed the execution permission.

**Impact.** The requirement "a raw adapter must not be able to bypass it" holds only if every code path that holds the gateway's DB credentials runs `bankExecutionDecision` first. Any second provider adapter, batch tool or hot-fix using the gateway role, or a compromised boundary combined with such a path, executes a payment the customer never signed. The docs present the `APPROVED` row as the authority (`bank-integration/README.md:30`) and admit the DB does not verify signatures (`bank-database-authorization.md:86-87`), but do not state that the gateway role alone needs no evidence.

**Fix (pick one).**
- Move verification into the trusted DB zone: an ECDSA-capable extension (e.g. a vetted C extension or `plv8` with a pinned verifier) used by `bank.approve` and `bank.submit` to check the HSM seal (pinned evidence keys stored in an owner-only table), the device signature and the bank statement signature.
- Or make the gateway's verification a separate signer: the gateway signs `(payment_id, attempt_id, order_hash, evidence_hash)` with a key in the bank HSM, and the provider adapter / core banking accepts only orders carrying that signature, verified by the core system, not by the adapter.
- At minimum: `bank.submit` requires a `p_verification` argument produced by a distinct `verifier` role that only records a verified decision (`bank.record_verification(payment, attempt, evidence_hash)`), so no single role both decides and sends.

**Regression test.** As `bank_gateway`, `bank.submit` for an execution whose evidence has an invalid seal must raise; as `bank_boundary`, `bank.approve` with a non-verifying device signature must return `ok = false`.

### C-03 (Medium) Execution is not time-limited in the bank's zone

`termsProblems` compares authorization ID, NEXUS ID, reference, amount, currency, operation type, beneficiary (`bankTrust.mjs:111-116`); `evidence_problem` the same (`schema.mjs:216-220`). Neither reads `issued_at`/`expires_at` (present in the canonical payload, `canonicalAuthorization.ts:19-20`). The forged signed bytes in C-02 contained no `expires_at` at all and were accepted by `bank.approve`. The lease (max 1 h, `schema.mjs:40`) bounds an attempt, not the permission: `claim` can renew indefinitely from `HELD`. Auth Core's `BANK_COMMIT_MAX_AGE_SECONDS` (`bankTransactionService.ts:77`) is not applied when the commit was already requested (`:60-65`), and a compromised Auth Core simply returns 202.

Impact: a payment the customer confirmed can be executed days later (e.g. after being `HELD`), contrary to "time-limited".

Fix: in `bankExecutionDecision` and `bank.evidence_problem`, require `signed.expires_at` and refuse when `verifiedAt`/sealed `verifiedAt` is after `expires_at`, or when `now() - verifiedAt > bank_max_age` (bank configuration, stored in an owner table read by `bank.approve`; the gateway re-checks at submit). Test: approve with evidence verified `bank_max_age + 1 s` ago → refused.

### C-04 (Medium) Registry role can permanently block credentials with unsigned statements

`approve_credential`/`revoke_credential` validate only the shape; the `signature` is any string (`schema.mjs:611-613, 630-632`). The resulting `credential_trust` row is checked by `bank.approve` (`:429-432`) and protected by `credential_trust_lifecycle` (binding immutable, revocation final, `:298-307`).
```
-- 30_bank_attacks.sh R2/R3, as bank_registry
approve_credential(cred 4444…, nexus 999999999, signature 'x')  -> ok
approve_credential(cred 4444…, nexus 123456789, signature 'genuine-bank-signature')
  ERROR: credential 44444444-… is approved for another customer
revoke_credential(cred 5555…, signature 'x')                    -> ok
approve_credential(cred 5555…, 'genuine')
  ERROR: credential 55555555-… was revoked; a new device gets a new credential
```
Doc `bank-database-authorization.md:85` says such a statement "counts nowhere". Impact: whoever obtains the registry DB login can make any customer unable to pay until the owner edits rows. Fix: derive `credential_trust` only from statements that a verifier accepted (see C-02 options), or let `bank.approve` and the conflict checks in `approve_credential` consider only statements whose signature was verified by a separate role; at minimum make the "other customer"/"revoked" conflicts depend on a statement row with a verified flag set by a different role. Test: an unsigned revocation does not stop a later valid approval.

### C-05 (Medium) Auth Core lifecycle enforced on UPDATE only

```
-- 22_core_insert_bypass.sql as nexus_app
INSERT INTO authorization_requests(..., expires_at, state, bank_transaction_state, signature, verified_at)
 VALUES (..., now()-interval '1 day', 'VERIFIED','COMMITTED', NULL, NULL)
 RETURNING state, bank_transaction_state, signature, verified_at, expires_at < now();
 VERIFIED | COMMITTED | | | t
INSERT ... bank_transaction_state = 'ANY_STRING_AT_ALL'  -> accepted
```
The UPDATE trigger refuses "VERIFIED needs a signature and verified_at" (`schema.sql:465-467`) but nothing checks it at INSERT. `docs/architecture/state-machines.md:3` says the lifecycles "are enforced by the database"; ADR 0013 (Consequences) admits inserts are uncovered. The bank does not trust these columns (good), but Auth Core's own `requestCommit` gate starts from `state = 'VERIFIED'` (`bankTransactionService.ts:59`) before the evidence check. Fix:
```sql
ALTER TABLE authorization_requests ADD CONSTRAINT authorization_requests_bank_state_check
  CHECK (bank_transaction_state IN ('PENDING','COMMIT_REQUESTED','COMMITTED','FAILED','CANCELLED'));
ALTER TABLE authorization_requests ADD CONSTRAINT authorization_requests_insert_shape
  CHECK (state <> 'VERIFIED' OR (signature IS NOT NULL AND verified_at IS NOT NULL));
CREATE OR REPLACE FUNCTION authorization_insert_state() RETURNS trigger LANGUAGE plpgsql
  SET search_path = pg_catalog, public AS $$
BEGIN
  IF NEW.state <> 'PENDING_USER' OR NEW.bank_transaction_state <> 'PENDING' OR NEW.signature IS NOT NULL
     OR NEW.verified_at IS NOT NULL OR NEW.consumed_at IS NOT NULL OR NEW.offline_code_tag IS NOT NULL THEN
    RAISE EXCEPTION 'authorizations are created PENDING_USER/PENDING' USING ERRCODE = 'integrity_constraint_violation';
  END IF; RETURN NEW; END $$;
CREATE TRIGGER authorization_insert_state BEFORE INSERT ON authorization_requests FOR EACH ROW EXECUTE FUNCTION authorization_insert_state();
```
Same for `credentials` (`state = 'ACTIVE'` on insert, `revoked_at IS NULL`). Test: the two INSERTs above fail as `nexus_app`.

### C-06 (Medium) Migration integrity cannot be established

`01_migrations.out`:
- (a) 002…022 on an empty database: the first statement of nearly every file fails (`002: relation "bank_clients" does not exist`, … `022: relation "authorization_requests" does not exist`). Note: psql exits 0 in my first loop because of a `$(…)` pipe; the errors are real. There is no migration 001 and no baseline file; README says 002 starts from "the pre-1.0 Auth Core schema" (`migrations/README.md:7`).
- (b)/(c)/(d) schema.sql, schema.sql + all migrations, twice each: sorted `pg_dump --schema-only` statements are IDENTICAL. So the migrations are re-runnable on top of schema.sql, but this is exactly what CI does (`README.md:52`), and it proves nothing about upgrading a real database: every `IF NOT EXISTS` is a no-op there.
- Minimal baseline (`bank_clients` only, `audit_c_baseline`): `003, 005, 006, 009, 015, 016, 017` fail (`recovery_sessions`, `webhook_deliveries`, `audit_logs` missing). Column diff (`cols_schema.txt` vs `cols_baseline.txt`) shows schema.sql has `authorization_requests.policy_decision` and `risk_context_reference` that no migration creates, and `authorization_attempts.result` is VARCHAR(32) in schema.sql but VARCHAR(24) in `002:90`.
- 013, 016 disable/re-enable the append-only trigger inside the migration; 018 drops `attestation_records`, `policy_decisions` (guarded: stops if rows), `credentials.suspended_at` and `nexus_identities.recovery_verifier` (unconditional data loss, intended; rollback only by restoring the pre-upgrade backup, `README.md:50`). No down scripts. No migration bookkeeping table: nothing records which migrations ran.

Impact: an existing bank deployment cannot be upgraded with confidence; drift between fresh and upgraded databases is undetectable by CI. Fix: commit the pre-1.0 baseline as `001_baseline.sql`; add a `schema_migrations(version, checksum, applied_at)` table and guard every migration; in CI apply 001…022 to an empty DB and diff against schema.sql (the script `01_migrations.sh` does this). Add `ALTER TABLE authorization_requests ADD COLUMN IF NOT EXISTS policy_decision…` to a migration or drop the columns from schema.sql (they are unused, C-17).

### C-07 (Low) Mutable audit fields

`21_core_attacks_app.out` A3/A6 as `nexus_app`:
```
UPDATE … SET consumed_at=NULL      -> UPDATE 1;  SET consumed_at='2001-01-01' -> UPDATE 1
(after COMMITTED) UPDATE … SET bank_commit_at='2001-01-01', bank_commit_error='rewritten' -> COMMITTED | 2001-01-01 | rewritten
INSERT INTO audit_logs(…, actor, "timestamp") VALUES (…,'admin:alice', now()-interval '400 days') -> accepted
```
Fix: add to `authorization_lifecycle`: `consumed_at` set once together with `verified_at`; `bank_commit_at`/`bank_commit_error` change only on the transition out of `COMMIT_REQUESTED`. For `audit_logs`: a BEFORE INSERT trigger `NEW."timestamp" := clock_timestamp()` and `NEW.actor` must be non-null; better, chain audit rows (hash of previous) like the evidence chain. Test: the statements above fail.

### C-08 (Low) Rewrap guard is caller-settable

```
UPDATE credentials SET offline_secret_encrypted='k1$attacker$x$y$z' …  -> ERROR keys … immutable
BEGIN; SELECT set_config('nexus.secret_rewrap','on',true);
UPDATE credentials SET offline_secret_encrypted='k1$attacker$x$y$z' … RETURNING …  -> k1$attacker$x$y$z
```
Swapping in another credential's ciphertext would not decrypt, because `decryptSecretBytes(encrypted,'device',credentialId)` uses the credential ID as AAD (`authorizationConfirmation.ts:216`, `secretBox.ts:80-96`). Impact: DoS of offline confirmation for that credential. Fix: make the rewrap a `SECURITY DEFINER` function `rewrap_offline_secret(credential, new_ct)` owned by `nexus_owner`, executable only by a separate `nexus_rotation` role, which sets a private flag; the trigger accepts the change only when `current_user = 'nexus_owner'` inside that function. Test: the BEGIN/set_config/UPDATE sequence fails as `nexus_app`.

### C-09 (Low) Kept head can be pushed to the maximum

```
SELECT bank.keep_head('123456789', 2147483647, repeat('0',64));  -> t
SELECT bank.keep_head('123456789', 5, repeat('1',64));           -> f   (forward only, permanently)
```
`executionBoundary.mjs:133` passes the kept head as `expectedHead`; `verifyEvidenceChain` then reports the chain as missing records (Suspected: not run, no Node `pg`). Fix: `keep_head` must take the evidence record (sealed payload + seal) and only the gateway/verifier role may advance it after verifying the seal, or cap advancement to `records actually verified`. Test: `keep_head` with a sequence beyond the verified chain is refused.

### C-10 (Low) No RLS; tenant isolation only in queries

`A13`: `tables_with_rls = 0` (none have RLS, none FORCE). `A5`: `nexus_app` sees bankA 2, bankB 1 rows. `A9`: `UPDATE bank_clients SET webhook_url='https://attacker.example', mtls_cert_sha256=ARRAY[…] WHERE client_id='bankB'` → `UPDATE 1`. One compromised Auth Core process or one SQL injection affects all banks; nothing in the DB separates them. Fix (if multi-tenant is offered): RLS on every table with `client_id` (`USING (client_id = current_setting('nexus.client_id'))`, `FORCE ROW LEVEL SECURITY`), with the setting set per request by a definer function; or one database per bank. Move `bank_clients`, `admin_users`, `verification_providers` writes to a separate admin role; `nexus_app` gets SELECT only.

### C-11 (Low) Nonce deletion not limited to expired rows

`roles.sql:59-60` grants `DELETE ON device_request_nonces` (comment: "Expired device request nonces"). A10: `DELETE FROM device_request_nonces WHERE expires_at > now()` → `DELETE 1`. Fix: revoke DELETE; add `SECURITY DEFINER FUNCTION purge_expired_device_nonces(limit int)` (owner, `SET search_path = pg_catalog, public`) that deletes only `expires_at < now()`, grant EXECUTE to `nexus_app`, and call it from `authorizationExpiry.ts:94`.

### C-12 (Low) Provider outcome model and reference provider

Distinct persisted states exist for: approved/command accepted by the bank (`APPROVED`), recorded before sending (`SUBMITTED`), provider processing (`PENDING_PROVIDER`), provider failed (`PROVIDER_FAILED`), unknown (`OUTCOME_UNKNOWN`), executed. There is no "provider rejected" (definitive refusal, e.g. validation error): `OUTCOME_SET = {succeeded, failed, pending}` (`paymentGateway.mjs:212`); any other answer becomes `unknown` (`:285-289`); `createHttpProvider.submit` returns `r.json()` for any status below 500 (`:393-394`), so a 4xx error body becomes `OUTCOME_UNKNOWN` → reconcile → `not_found` → REVIEW or resubmission. `createHttpProvider` sends orders with no authentication, no client certificate and no signature (`:388-403`). Fix: add `PROVIDER_REJECTED` (final, no money moved) mapped from an explicit provider status; require the real adapter to authenticate to the core system (mTLS and signed order, see C-02).

### C-13 (Low) REVIEW resolution

`bank.resolve_review` lets one operator mark `EXECUTED`/`PROVIDER_FAILED` with a note (`schema.mjs:647-661`); `createOperatorTools` does not inform Auth Core (`registry.mjs:42-47`). Fix: two operators (requested/approved, as `admin_approvals` does in Auth Core), then `commitResult`.

### C-14 (Low) Redis-only state

In Redis only: bank OAuth access tokens (`tokenService.ts:48`), admin sessions (`adminAuthService.ts:124-153`), mobile sessions (`mobileSessionService.ts:43-66`), brute-force counters and lockouts (`bruteForceProtection.ts:35-58`), recovery setup salts (`recoveryService.ts:102-122`), call operator claims (`verificationCall.ts:144-191`). On loss/flush, sessions and tokens fail closed (re-login); lockouts reset (fail open for throttling); a recovery setup must restart. Device request nonces are in PostgreSQL by default (`env.ts:120` `DEVICE_NONCE_STORE` default `postgres`) and `productionPosture.ts:41` blocks `redis` in production, so a Redis flush does not allow device-request replay. Offline codes and authorization states are in PostgreSQL. Fix: keep lockout counters for recovery and admin login in PostgreSQL as well, or accept and document.

### C-15 (Info) Auth Core trigger functions not hardened

`22_core_insert_bypass.out`: all nine trigger functions `prosecdef = f`, `proconfig` empty; `nexus_app` has `TEMP`. A12: a `pg_temp.secret_rewrap_allowed()` returning true with `search_path = pg_temp, public` did not change the outcome (functions are never resolved from `pg_temp`), so not exploitable now. Fix: `ALTER FUNCTION … SET search_path = pg_catalog, public` for each and `REVOKE TEMPORARY ON DATABASE … FROM PUBLIC` in `roles.sql`.

### C-16 (Info) Owner powers

`23_core_owner.out`: `nexus_owner` disables `trg_evidence_append_only` and rewrites a signature; `TRUNCATE offline_deferred_signatures` succeeds (no TRUNCATE trigger, unlike `evidence_records`/`audit_logs`). Same for `bank_owner` on `bank.executions` (`30_bank_attacks.out` O1). Documented residual risk; add a TRUNCATE trigger to `offline_deferred_signatures`.

### C-17 (Info) Model and naming

- Unused: `authorization_requests.policy_decision`, `risk_context_reference` (0 references in `src/`), `webhook_deliveries.delivery_attempt_id`, `event_created_at`, `evidence_records.evidence_hash_algorithm` (constant default).
- Duplicate state: `consumed_at` is set with `verified_at` in the same update (`authorizationConfirmation.ts:387`) and never read for single-use; single use is `bank_transaction_state` in Auth Core and `bank.payments.authorization_id UNIQUE` in the bank. Auth Core `bank_transaction_state` duplicates the bank journal (documented as non-authoritative, `payment-state-machine.md:16`).
- Mixed `state`/`status` column names (`authorization_requests.state`, `credentials.state`, `bank_clients.status`, `nexus_identities.status`, `bank.payments.status`, `bank.executions.state`); `PENDING` means different things in five tables; `FAILED` (Auth Core) vs `PROVIDER_FAILED` (bank).
- ADR 0013 still lists `CREATED`, `DELIVERING`, `SIGNED`, `CONSUMED`, credential `PENDING`/`SUSPENDED` (removed by 018).
- When the bank omits `operationType` from terms, neither `evidence_problem` (`schema.mjs:220`) nor `termsProblems` (`bankTrust.mjs:119`) compares the signed `operation_type`, and the order sent has `"operationType": null` (`30_bank_attacks.out` G1). Make it required.

### C-18 (Info) Backup, restore, retention

No backup, restore or retention script exists (no `pg_dump`, `pg_basebackup`, `pgbackrest`, `wal-g` anywhere). `disaster-recovery.md:9-10` has placeholders `<provider / tooling>`; the only retention code purges expired device nonces (`authorizationExpiry.ts:94-99`). Bank-side restore behaviour is wrong (C-01).

## 4. Questions asked in the brief, answered

**In-memory execution adapter.** None remains in `bank-integration/`: no Map/Set/boolean decides execution (only constant sets `TRIGGERS`, `OUTCOMES`, `allowedClients`). The decision inputs are the bank DB (`bank.*`) plus `bankExecutionDecision`. `demo/bank-backend/demo-bank.mjs:77` keeps payments in an array but executes nothing (`:214`). Auth Core's in-memory `SoftwareHsmAdapter` is refused in production (`productionPosture.ts:14-15`).

**Webhook.** `webhookHandler.mjs:21-35` checks HMAC and a 300 s timestamp window (no replay cache) and only calls `boundary.execute(paymentId)`; content is not used for the decision. A forged or replayed webhook can only trigger an attempt.

**Can a compromised Auth Core (webhook HMAC key + HSM sealing key) cause a payment the device never signed? No**, on the reference code path: `bankExecutionDecision` (boundary `executionBoundary.mjs:131` and again gateway `paymentGateway.mjs:251`) verifies the device ECDSA signature over the signed bytes (`evidence.mjs:128-…`) with `credentialPublicKeyPem`, and requires that key's SHA-256 fingerprint to be in a statement signed by the bank's own trust key (`bankTrust.mjs:73-104`); offline codes without a device signature are refused (`rejectOfflineCode = true`, `bankTrust.mjs:140`). Holding the sealing key lets Auth Core seal anything, but not produce a device signature for a bank-approved key. Conditions: (1) the bank's approval workflow takes the fingerprint from the device/SDK, not from Auth Core (`bank-trust-statement.mjs:11-13`; that workflow is not in the repository: UNVERIFIED); (2) every path to the provider runs the gateway JS (C-02); (3) the bank DB is not restored (C-01). It can still: delay or deny (refuse commits), trigger early execution attempts, and execute a genuinely signed payment late (C-03).

**Real core-banking adapter?** No. `createHttpProvider` is a reference HTTP client to a provider contract; the tests use a provider double; `bank-integration/README.md:13` says so.

## 5. Security properties verified as correctly enforced

| Property | Location | Evidence |
|---|---|---|
| Every `bank.*` function owned by `bank_owner`, mutating ones `SECURITY DEFINER` with `search_path=pg_catalog, pg_temp`; internal helpers not definer; no PUBLIC EXECUTE; each role executes only its own | `schema.mjs:97, 173-661, 696-719` | `10_bank_function_inventory.out` |
| No bank role has TEMP, CREATE on public, or any table write | `schema.mjs:668-671, 711-718` | same; `30` P3: `permission denied for table executions` |
| `bank.via` GUC forging gives nothing; internal functions not callable | `schema.mjs:174-175, 230-267` | P3: `set_config('bank.via','approve')` then INSERT → permission denied; `bank.via()` and `evidence_problem()` → permission denied |
| Boundary cannot submit | grants | G0 `permission denied for function submit` |
| Single use: second `submit`, `resubmit` after final, claim after final | `schema.mjs:530-565, 391` | G2, G4 |
| One payment per authorization; evidence bound to the payment's authorization | `schema.mjs:125, 204` | P1 duplicate key; `the evidence is for another authorization` |
| Expired lease cannot approve | `schema.mjs:422` | P2 `the claim was lost` |
| Terms immutable and log append-only even for the owner | `schema.mjs:271-285, 311-330` | P4 |
| Transition log records login role and function | `schema.mjs:264-265` | L: `bank_boundary/claim`, `bank_gateway/submit` |
| `nexus_app` cannot ALTER/DROP/TRUNCATE/disable triggers; cannot UPDATE/DELETE evidence or audit | `roles.sql:37-63`, `schema.sql:213-263` | A1, A2 |
| Authorization binding immutable; illegal transitions and re-signing refused | `schema.sql:428-513` | A6: `transaction is immutable`, `VERIFIED -> PENDING_USER is not permitted`, `signature fields are set once`, `PENDING -> COMMITTED`, `COMMITTED -> PENDING`, reference change refused |
| One evidence record per authorization | `schema.sql:171` | A4 unique violation |
| Credential keys immutable; REVOKED final | `schema.sql:525-551` | A8 |
| Deletes of security rows refused | `roles.sql:56-60`, `schema.sql:609-623` | A11 |
| Concurrent confirmations: one wins, other updates 0 rows or is refused by the trigger | `schema.sql:458-464` | `24_race.out` variants A and B, final `sig-session1` |
| Migrations idempotent on top of schema.sql | — | `01_migrations.out` (d) IDENTICAL |
| PostgreSQL nonce store default and enforced in production | `env.ts:120`, `productionPosture.ts:41`, `mobileAuth.ts:169-177` | code reading |

## 6. Docs vs reality

| Statement | Reality |
|---|---|
| "nothing is executed again" after restore (`pilot-execution-pack.md:177`) | Re-sent (C-01) |
| Authority to send is the `APPROVED` row (`bank-integration/README.md:30`) | `APPROVED` reachable with forged evidence; gateway role sends without evidence check (C-02) |
| A bad-signature statement "counts nowhere" (`bank-database-authorization.md:85`) | Blocks approvals permanently (C-04) |
| Lifecycles "enforced by the database" (`state-machines.md:3`) | UPDATE only; INSERT bypass (C-05) |
| CI applying schema.sql then migrations verifies migrations (`migrations/README.md:52`) | No-op; real upgrade path untested, baseline missing (C-06) |
| `nexus_app` DELETE only expired nonces (`roles.sql:14-15`) | Any nonce (C-11) |
| ADR 0013 state lists | Stale (C-17) |
| DR: backup/PITR method | Placeholder, no tooling (C-18) |

## 7. Feature status

| Feature | Status |
|---|---|
| Auth Core schema, append-only evidence/audit, UPDATE lifecycle triggers | IMPLEMENTED |
| Auth Core state machine at INSERT | MISSING |
| Migration path from a real pre-1.0 database (baseline 001, bookkeeping) | MISSING |
| Role separation `nexus_owner`/`nexus_app`/`nexus_audit_reader` | IMPLEMENTED |
| Tenant isolation in the database (RLS) | MISSING |
| PostgreSQL device nonce store (default, production-enforced) | IMPLEMENTED |
| Bank schema with definer functions, pinned search_path, per-role grants | IMPLEMENTED |
| Cryptographic verification inside the bank DB | MISSING (JS in boundary and gateway only) |
| Bank execution decision (device signature + bank-approved key + pinned seal) | IMPLEMENTED (JS) |
| Time limit on execution in the bank zone | MISSING |
| Single-use, per-transaction execution permission | IMPLEMENTED (DB) |
| Separate states approved / submitted / processing / failed / unknown | IMPLEMENTED |
| Distinct "provider rejected" state | MISSING |
| Real core-banking / provider adapter | MOCKED (reference HTTP client, provider double in tests) |
| Bank approval workflow taking the fingerprint from the device | UNVERIFIED (not in repo) |
| Safe bank-journal restore | MISSING (C-01) |
| Backup / restore / retention tooling | MISSING (docs only) |
| Real HSM, real provider idempotency/lookup guarantees | BLOCKED EXTERNAL |
| Repository integration tests (`*.test.mjs`) | UNVERIFIED (cannot run: no `pg` module) |
