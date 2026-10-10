# 0004. Append-only evidence chain

## Status

Accepted

## Date

2026-09-29

## Context

Evidence of an authorization is read by people who do not trust Auth Core, its database or its operators: internal and external auditors, court experts, the customer's representative. A record signed only by the bank's HSM shows that the bank sealed it, and nothing about what the customer signed. A table that the application can update allows records to be changed or removed without trace.

## Decision

- Each verified authorization produces one record in `evidence_records`. Its `sealed_payload` is stored verbatim; `evidenceHash = hex(SHA-256(canonicalJson(sealedPayload)))`, and the HSM signs the 32 hash bytes with the evidence key (`sealEvidence` in `evidenceService.ts`).
- Schema version 2 puts into the sealed payload the canonical bytes the device signed (`signedPayloadBase64`), the device signature, its format and the device public key (`credentialPublicKeyPem`), next to the verification factors and their assertion hashes.
- Records of one NEXUS ID form a hash chain through `previousEvidenceHash`. A transaction-scoped advisory lock per NEXUS ID allows one writer at a time, and `created_at` is `clock_timestamp()` so the order of the chain follows insert order.
- Migration `009_evidence_v2_append_only.sql` adds triggers that reject `UPDATE`, `DELETE` and `TRUNCATE` on `evidence_records` for every role.
- `scripts/verify-evidence.mjs` checks hash, seal, signed bytes, device signature and chain with Node.js only and imports no Auth Core code.

## Consequences

- The HSM key holder can seal any record but cannot produce a device signature over terms the customer did not sign. The holder of a device key can sign but cannot place a record in the sealed chain.
- Removing, reordering or substituting a record breaks the chain or a seal.
- The trigger does not stop a database administrator; banks that need more export records to WORM storage or a SIEM.
- Records sealed under evidence schema 1 have no sealed payload and are reported as unsupported by the verifier.
- Offline-code records are sealed and chained the same way, but the customer's part is not third-party verifiable ([ADR 0003](0003-offline-confirmation-hmac-codes.md)).
- Evidence contains beneficiary data as signed, so retention and access to exports follow the bank's data protection rules.
- Format and verification rules: [evidence-format.md](../protocol/evidence-format.md).
