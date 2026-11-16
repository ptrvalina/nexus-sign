# Security architecture

How NEXUS-SIGN is protected, layer by layer, and which control answers which threat. The adversaries, invariants and residual risks are in the [threat model](../security/threat-model.md); keys and algorithms in the [cryptographic architecture](CRYPTOGRAPHIC_ARCHITECTURE.md). Branch `engineering/production-readiness`.

## Components and trust

```
 Customer's phone                     Bank                                   NEXUS-SIGN (inside the bank)
 ┌──────────────────────┐   TLS   ┌──────────────────────┐  mTLS   ┌──────────────────────────────┐
 │ Bank app             │◀──────▶│ Bank backend          │◀──────▶│ API gateway + WAF (bank's)    │
 │  └ NEXUS-SIGN SDK    │         │  └ bank database      │        │   └ Auth Core (N instances)   │
 │     Secure Enclave / │         │     (own approval of  │        │       ├ PostgreSQL (HA)       │
 │     Keystore keys    │         │      each device key, │        │       ├ Redis (TLS)           │
 └──────────▲───────────┘         │      own signature    │        │       └ HSM (PKCS#11)         │
            │ device-signed       │      check, P-256 in  │        └──────────────────────────────┘
            └─────────────────────│      the database)    │
              requests via gateway└──────────────────────┘
```

| Party | Trusted for | Not trusted for |
|---|---|---|
| Secure hardware of the phone | Keeping the private keys and enforcing the biometric | — |
| The bank app process | Showing the SDK's screens | Holding any secret that confirms a payment (D-01 is the exception on iOS) |
| Auth Core | Relaying, checking and sealing; availability | Deciding that money moves: the bank verifies independently |
| The HSM | Keeping the evidence key and the KEK | — |
| The bank backend | Creating authorizations, approving device keys, executing | Changing what the customer signed; replacing a device without a hold |
| Console staff | Operating within their bank | Acting alone on revocation, reactivation or lifting a mandate hold (four eyes) |

## Controls by layer

### Device (SDKs)

- Keys generated in secure hardware, biometric per use (`.biometryCurrentSet`, `setInvalidatedByBiometricEnrollment`); dead keys deleted after a biometric change on both platforms ([biometric behaviour](../architecture/biometric-behaviour.md)).
- Attestation at enrolment: App Attest (iOS), Key Attestation + Play Integrity (Android), bound to the session challenge and all enrolled keys.
- What-you-see-is-what-you-sign: parse the exact canonical bytes, refuse anything non-canonical, duplicate keys, unknown fields, unsafe display text, IBAN look-alikes; labelled prompt text ([D-02](../protocol/authorization-protocol-v1.md#confirmation-text)).
- Every request signed by the device request key with a one-time nonce and a time window; optional certificate pinning.
- Secure push: content sealed per device (AES-256-GCM), receipts MACed.

### Network

- mTLS between the bank backend and the gateway; the gateway overwrites the client-certificate headers; Auth Core checks the gateway's address (`TRUSTED_PROXY_IPS`) and the certificate fingerprint per bank client. Device routes are exempt from mTLS and authenticated by device signatures instead (`mtlsGateway.ts`, derived from `openapi.yaml` in a test).
- TLS to PostgreSQL and Redis is a production startup requirement.
- Kubernetes NetworkPolicy limits ingress to the gateway and monitoring and egress to the datastores, the HSM and the egress proxy ([manifests](../../deploy/kubernetes/README.md)).
- Webhooks only to allow-listed HTTPS hosts; SSRF checks on resolution.

### Auth Core (application)

- Fail-closed startup: `productionBlockers()` refuses to start without the HSM, attestation, TLS, mTLS, admin MFA, wrapped master keys and other controls ([configuration](../operations/configuration.md#production-blockers)); the Kubernetes manifests are checked against the same function.
- Authentication: bank clients by OAuth client credentials + mTLS; devices by request signatures; console staff by password + TOTP, `SameSite=Strict` cookie, same-origin check, throttled logins.
- Authorization: every bank API call is scoped to the client's own identities; every device call to its own NEXUS ID; console reads to the admin's bank (platform accounts read-only), changes to the bank's own operators; four eyes for identity revocation and reactivation and for lifting a mandate hold.
- State machines enforced in services and again in the database (authorizations, mandates, conversations, customer calls, device requests).
- Replacement hold: a bank cannot move a customer to a new device at once; the enrolled device can approve or cancel ([device replacement](../architecture/device-replacement.md)).
- Customer limits and their relaxation delay; mandate debits checked twice.
- HSM in a worker thread with timeouts, a bounded queue and a circuit breaker that fails closed.
- No request bodies or key material in logs; every security-relevant action in the append-only audit log, exportable to a SIEM ([monitoring](../operations/monitoring.md#siem-export-of-the-audit-log)).

### Database

- Roles: `nexus_owner` (NOLOGIN, owns everything), `nexus_app` (no ownership, cannot disable triggers, no TRUNCATE, INSERT/SELECT only on evidence and audit), `nexus_audit_reader` ([roles.sql](../../auth-core/scripts/db/roles.sql)).
- Append-only and lifecycle triggers on evidence, audit, outcomes, mandates, debits, conversations, customer calls; insert-state trigger on authorizations; device limit enforced by a trigger.
- Migrations with a checksummed ledger and a lock; restore keeps triggers and a verifiable chain (tested).

### Evidence

- Every authorization, outcome, enrolment, revocation, recovery configuration and mandate event sealed with the HSM key in the transaction of the change (outcomes via a recorded queue sealed by the worker); chained per NEXUS ID; the bank keeps chain heads; offline verifier in `scripts/verify-evidence.mjs`.

### The bank's independent decision

- The bank database verifies the device's P-256 signature itself (PL/pgSQL), checks that the key is one the bank approved with its own trust key and has not revoked, that the terms are the ones it asked for, and the chain head; for mandates the signed terms, period and limits. A compromised Auth Core cannot make the bank execute (`bank-trust-compromise.test.mjs`, SoftHSM suite) ([bank database authorization](../security/bank-database-authorization.md)).

## Threat → control

| Threat | Primary control | Second line |
|---|---|---|
| Stolen phone | Biometric per key use; customer suspends from another device or the bank console | Bank revokes; replacement hold |
| Malware in the app process | Keys in hardware; prompt shows signed bytes | Bank-side signature check; D-01 limits iOS offline codes to provisional |
| Bank backend credentials stolen | mTLS + client scope; device replacement hold; display rules | Customer cancels the replacement; bank's own approvals |
| Auth Core compromised | Bank verifies signatures and approvals independently | Evidence chain heads held by the bank |
| Database tampering | Triggers, roles | Sealed evidence, offline verification, metadata binding |
| Malicious console operator | Bank scope, audit by name | Four eyes for revocation, reactivation, hold release |
| Payee confusion (look-alikes, second account number) | Display text rules, labelled prompt | Bank's own payee verification (Verification of Payee) |
| Replay | One-time nonces, single-use authorizations and tokens | Idempotency keys; database uniqueness |
| HSM stall | Worker thread, timeouts, breaker | Readiness reports down; outcomes queued and sealed later |

## Not covered, or not yet shown

External penetration test, load and resilience tests, a production HSM, devices, and a cryptographic review have not happened. The open findings and their decisions are in the [findings register](SECURITY_FINDINGS.md).
