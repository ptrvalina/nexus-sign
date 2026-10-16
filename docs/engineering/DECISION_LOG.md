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
