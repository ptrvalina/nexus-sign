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
