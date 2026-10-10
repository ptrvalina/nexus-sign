# 0009. Evidence schema 3: sealed key provenance and numbered chains

## Status

Accepted

## Date

2026-10-06

## Context

Evidence schema 2 ([ADR 0004](0004-append-only-evidence-chain.md)) sealed each confirmed authorization with the signed bytes, the device signature and the device public key. The public key was copied from the `credentials` row at the time of sealing. Someone able to write to the database could replace a credential's public key with their own, sign a transaction, and obtain a record that verified: the HSM sealed whatever key the row held, and nothing outside the database said which key had been enrolled for the customer.

The chain was linked by `previousEvidenceHash` only. Removing records from the end of a chain left a shorter chain that still verified, and the order of records depended on `created_at`.

## Decision

- Evidence schema 3 (migration 013) keeps one chain per NEXUS ID with three record types: `AUTHORIZATION`, `CREDENTIAL_ENROLLED` (the public keys of a credential, its platform and security level, the attestation material that admitted it, the credentials it replaced and the bank's replacement authorization) and `RECOVERY_CONFIGURED` (the recovery public key a device registered, [ADR 0010](0010-recovery-protocol-v2.md)).
- Every record seals `schemaVersion`, `recordType`, `nexusId`, `chainSequence` (1, 2, 3 …), `previousEvidenceHash` and `sealKeyId` (SHA-256 of the HSM key's SubjectPublicKeyInfo).
- An `AUTHORIZATION` record seals `enrolmentEvidenceHash`, the hash of its credential's `CREDENTIAL_ENROLLED` record.
- Unique indexes on `(nexus_id, chain_sequence)`, on `(nexus_id, previous_evidence_hash)` and on the first record of each chain reject forks, in addition to the advisory lock.
- Before using a credential's keys (device-signed requests, `SESSION` tokens, confirmations, recovery setup), Auth Core compares them with the credential's sealed enrolment after checking its seal (`credentialIntegrity.ts`), refuses on a mismatch and audits `integrity_violation`. (`SESSION` tokens were removed in 2.0.0-rc.2, [ADR 0016](0016-remove-compatibility-paths.md).)
- The chain head `{evidenceId, chainSequence, evidenceHash}` is returned to the bank with identities, authorizations, confirmation results and chain exports. `verify-evidence.mjs` checks numbering, links and key provenance, verifies seals with the key each record names from a keyring (`--public-keys`), and detects truncation against a head the bank kept (`--expect-head`).
- Retired evidence keys are configured in `EVIDENCE_RETIRED_PUBLIC_KEYS_PEM` and published with the current key in `evidencePublicKeys`.
- Credentials enrolled before 2.0 are sealed once on upgrade with reason `BASELINE` (`node dist/cli/sealCredentialBaseline.js`).

## Consequences

- A database writer who replaces a credential's key cannot approve a transaction, and an auditor can check that every schema 3 approval was signed by a key whose enrolment is earlier in the same sealed chain.
- Records removed from the end of a chain are detected only against a head the bank stored. Banks have to keep the latest head per NEXUS ID.
- A baseline record states what the database held at upgrade time, not how the keys got there. The baseline run belongs in the controlled upgrade window, and Auth Core refuses credentials that have not been sealed.
- Schema 2 records keep verifying, without key provenance; their chain number was assigned by the migration and is not sealed. Schema 1 records no longer pass the verifier.
- Exports grow by one enrolment record per credential, and a single-authorization export carries its enrolment record.
- The attestation material is kept for re-checking by third parties; the shipped verifier does not re-check it.
- Specification: [evidence format](../protocol/evidence-format.md). Tests: `test/evidence.test.mjs`, `test/integration/evidence-integrity.test.mjs`.
