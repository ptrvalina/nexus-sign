# Evidence format and offline verification

Every authorization that Auth Core accepts, every device credential it registers and every recovery key a device configures produces one sealed evidence record. The records are designed to be checked by someone who does not trust Auth Core, its database or its operators: an internal auditor, an external auditor, a court expert or the customer's representative in a dispute.

This page describes evidence schema version 3 (release 2.0, migration 013, [ADR 0009](../adr/0009-evidence-schema-3.md)). Implementation: `auth-core/src/services/evidenceService.ts`; independent verifier: `auth-core/scripts/verify-evidence.mjs` with `scripts/lib/evidence.mjs`.

## What the records prove

A valid chain shows five things, each checkable offline:

1. **The customer's device key signed exactly these transaction terms.** An `AUTHORIZATION` record contains the canonical bytes the device displayed and signed, the device signature and the device public key.
2. **That key was the one enrolled for the customer.** The `AUTHORIZATION` record names the `CREDENTIAL_ENROLLED` record of its credential, which sealed the device keys and the attestation that admitted them when the credential was registered.
3. **The bank sealed the records.** The bank's HSM signed the hash of each record, and the record names the HSM key (`sealKeyId`).
4. **No record has been removed, reordered or inserted.** Records of one NEXUS ID form a numbered hash chain, and the bank keeps the latest position it received (the chain head), so records removed from the end are detected as well.
5. **Which verification factors were completed.** Audio and video checks are listed with how they were closed: `method: PROVIDER` with the issuing provider key (`issuer`), the token's `jti` (`providerReference`) and the SHA-256 of the result token, which Auth Core verified before accepting it ([verification result v1](verification-result-v1.md)); or `method: OPERATOR` with the bank operator's username. The factor records who stated the result, not how it was reached. Records sealed before 2.0.0 list factors without `method`; their assertion was not verified by Auth Core.

The HSM seal and the customer signature are independent. The holder of the HSM key can seal any record, but cannot produce a customer signature over terms the customer did not sign. The holder of a device key can sign, but cannot place a record in the bank's sealed chain. Point 2 closes the gap between them: someone who can write to the database cannot swap a credential's public key for their own and have the resulting approval verify, because the key no longer matches the sealed enrolment.

## Record types

| `recordType` | Written when | Body |
|---|---|---|
| `AUTHORIZATION` | An authorization becomes `VERIFIED`, in the transaction that consumes it | Signed bytes, device signature and key, `enrolmentEvidenceHash`, policy, verification factors |
| `CREDENTIAL_ENROLLED` | A credential is registered (enrolment, replacement, recovery) or sealed once on upgrade (`BASELINE`), in the transaction that creates it | The credential's public keys, platform, security level, attestation material, replaced credentials, the bank's replacement authorization |
| `RECOVERY_CONFIGURED` | A device registers a recovery key ([recovery protocol 2](recovery-protocol-v2.md)) | The recovery public key, the SHA-256 of the wrapped key, the KDF salt and iterations |
| `AUTHORIZATION_OUTCOME` | An authorization ends without a confirmation: `REJECTED` (declined by the customer, signature attempts exhausted, verification failed), `EXPIRED`, `CANCELLED` (by the bank, or because the device or identity was revoked, suspended, replaced or recovered) or `OFFLINE_UNSIGNED` | `outcomeId`, `authorizationId`, `credentialId`, `transactionReference`, `canonicalPayloadHash`, `operationType`, `amountMinor`, `currency`, `issuedAt`, `expiresAt`, `outcome`, `reason`, `occurredAt`, `policyReference`, `policyVersion`, `credentialState`, `device` (`platform`, `securityLevel`), `enrolmentEvidenceHash`, `correlationId`, `verificationFactors` |
| `CREDENTIAL_REVOKED` | A credential is revoked (by the bank, by replacement, recovery or identity revocation) | `outcomeId`, `credentialId`, `reason`, `revokedAt`, `device`, `enrolmentEvidenceHash` |

All types share one chain per NEXUS ID.

### How outcomes reach the chain

Outcome records are not written by the code path that ends the authorization. A database trigger (migration 025) records the outcome in `evidence_outcomes` in the same transaction as the state change, whichever code or session made it, with the reason the transaction set (`nexus.outcome_reason`) or a default for the state. The expiry worker seals pending outcomes into the chain every `AUTHORIZATION_EXPIRY_SWEEP_MS` and links each to its record once; `evidence_outcomes` rows cannot be deleted or rewritten. While the HSM is unavailable outcomes stay pending and are sealed when it returns; the worker logs an error when the oldest pending outcome is older than 5 minutes. An outcome record therefore follows its state change by up to one sweep interval, and the `authorization.*` webhook that announced the outcome may arrive before it.

## Sealed fields

Every schema 3 record seals:

| Field | Content |
|---|---|
| `schemaVersion` | `"3"` |
| `recordType` | One of the types above |
| `nexusId` | The NEXUS ID whose chain the record belongs to |
| `chainSequence` | Position in the chain: 1 for the first record, then 2, 3 … |
| `previousEvidenceHash` | `evidenceHash` of the record at `chainSequence - 1`; `null` for the first record |
| `sealKeyId` | Lowercase hex SHA-256 of the DER SubjectPublicKeyInfo of the HSM evidence key that sealed the record |

```text
evidenceHash = hex(SHA-256(canonicalJson(sealedPayload)))
hsmSignature = base64(DER(ECDSA-P256-SHA256(evidence key, the 32 bytes of evidenceHash)))
```

`canonicalJson` sorts object keys recursively and uses `JSON.stringify` escaping, UTF-8, as in [protocol v1](authorization-protocol-v1.md). Auth Core refuses to seal a record if the HSM reports a different key from the one named in `sealKeyId`.

### AUTHORIZATION

```json
{
  "evidenceId": "…",
  "recordType": "AUTHORIZATION",
  "authorizationId": "…",
  "nexusId": "123456789",
  "credentialId": "…",
  "chainSequence": 7,
  "sealedPayload": {
    "schemaVersion": "3",
    "recordType": "AUTHORIZATION",
    "nexusId": "123456789",
    "chainSequence": 7,
    "previousEvidenceHash": "<hex>",
    "sealKeyId": "<hex>",
    "authorizationId": "…",
    "credentialId": "…",
    "transactionReference": "TX-2026-000154",
    "canonicalPayloadHash": "<hex SHA-256 of the signed bytes>",
    "signedPayloadBase64": "<the canonical authorization bytes, protocol v1>",
    "credentialPublicKeyPem": "-----BEGIN PUBLIC KEY-----…",
    "enrolmentEvidenceHash": "<evidenceHash of the credential's CREDENTIAL_ENROLLED record>",
    "signature": "<device signature, base64>",
    "signatureFormat": "der",
    "signatureAlgorithm": "ES256",
    "confirmationMethod": "DEVICE_SIGNATURE",
    "keyVersion": 1,
    "policyReference": "TRANSFER",
    "policyVersion": "2026-09",
    "attestationVerdict": "VERIFIED",
    "verifiedAt": "2026-10-06T10:00:00.000Z",
    "result": "VERIFIED",
    "correlationId": null,
    "verificationFactors": [
      { "channel": "AUDIO", "status": "VERIFIED", "method": "PROVIDER", "issuer": "<providerId>/<keyId>", "providerReference": "<jti>", "assertionHash": "<hex>", "completedAt": "…" }
    ]
  },
  "evidenceHash": "<hex>",
  "previousEvidenceHash": "<hex or null>",
  "hsmSignature": "<base64 DER>",
  "hsmKeyVersion": 1,
  "sealKeyId": "<hex>",
  "schemaVersion": "3",
  "createdAt": "…"
}
```

The fields outside `sealedPayload` are database metadata. The verifier checks that they agree with the sealed values; only the sealed values are evidence.

### CREDENTIAL_ENROLLED

```json
{
  "schemaVersion": "3", "recordType": "CREDENTIAL_ENROLLED", "nexusId": "123456789", "chainSequence": 1,
  "previousEvidenceHash": null, "sealKeyId": "<hex>",
  "credentialId": "…",
  "reason": "ENROLMENT",
  "enrolledAt": "…",
  "platform": "ANDROID",
  "securityLevel": "STRONGBOX",
  "keys": { "signingPublicKeyPem": "…", "authPublicKeyPem": "…", "offlinePublicKeyPem": "…" },
  "attestation": { "status": "VERIFIED", "bindingSha256": "<hex>", "material": { "format": "android-play-integrity+key-attestation", … } },
  "replacedCredentialIds": [],
  "replacementAuthorization": null
}
```

| Field | Content |
|---|---|
| `reason` | `ENROLMENT`, `REPLACEMENT` (a bank-authorized [device replacement](../architecture/device-replacement.md)), `RECOVERY`, `BASELINE` (sealed on upgrade, below). Chains written by 1.x and 2.0.0-rc.1 may also contain `ROTATION` and `BANK_PROVISIONED`, from the removed bank-side provisioning; verifiers accept any reason string |
| `securityLevel` | Taken from the verified attestation (`SECURE_ENCLAVE`, `TEE`, `STRONGBOX`); the client's claim only where attestation was not verified, which production does not allow |
| `attestation.status` | `VERIFIED` or `UNKNOWN`; a `BASELINE` record carries the status stored for the credential |
| `attestation.bindingSha256` | SHA-256 of the attestation binding (challenge and the three public keys); `null` where no attestation was run |
| `attestation.material` | `apple-app-attest`: the App Attest attestation object, key ID and environment. `android-play-integrity+key-attestation`: the SHA-256 of the Play Integrity token, the decoded device verdicts, the Keystore attestation chains and the derived security level. `none`: no material, with the reason or a note |
| `replacedCredentialIds` | Credentials revoked by this registration |
| `replacementAuthorization` | For a replacement: `method`, `reference` and `clientId` as the bank stated them |

The App Attest object and the Android Keystore chains are kept so that a third party can re-check them against Apple's and Google's roots. A Play Integrity token can be decoded only by Google, so only its digest and the verdict Auth Core received are kept. `verify-evidence.mjs` does not re-check attestation material; it checks that the record is sealed and carries the keys.

### RECOVERY_CONFIGURED

```json
{
  "schemaVersion": "3", "recordType": "RECOVERY_CONFIGURED", "nexusId": "123456789", "chainSequence": 2,
  "previousEvidenceHash": "<hex>", "sealKeyId": "<hex>",
  "credentialId": "<the device that registered the key>",
  "configuredAt": "…",
  "recoveryProtocol": 2,
  "recoveryPublicKeyPem": "…",
  "wrappedRecoveryKeySha256": "<hex>",
  "kdfSaltB64": "<base64>",
  "kdfIterations": 210000
}
```

## Chain rules

| Rule | Enforced by |
|---|---|
| One writer per chain at a time | Transaction-scoped advisory lock on the NEXUS ID while the next position is read and the record inserted |
| One record per position | Unique index on `(nexus_id, chain_sequence)` |
| One successor per record | Unique index on `(nexus_id, previous_evidence_hash)` where it is not `NULL` |
| One first record per chain | Unique index on `nexus_id` where `previous_evidence_hash` is `NULL` |
| Records are never changed or removed | Append-only trigger on `UPDATE`, `DELETE`, `TRUNCATE` (migration 009); the application role has `INSERT` and `SELECT` only (`scripts/db/roles.sql`) |
| An `AUTHORIZATION` record has its transaction fields | `CHECK` constraint on `record_type = 'AUTHORIZATION'` |

The indexes reject a fork even if the advisory lock were bypassed.

## Chain head

The head is the latest record of a chain: `{ "evidenceId", "chainSequence", "evidenceHash" }`. The bank keeps the latest one it received for each NEXUS ID; with it, a verifier detects records removed from the end of a chain, which hash links alone cannot show.

| Response | Field | Value |
|---|---|---|
| `GET /v1/nexus-identities/{nexusId}` | `evidenceHead` | The chain's latest record, or `null` |
| `GET /v1/nexus-identities/{nexusId}/evidence` | `head` | The chain's latest record at the time of the export |
| `GET /v1/authorizations/{id}` | `evidence` | Position of this authorization's record, or `null` before it is `VERIFIED` |
| Confirmation result (`POST …/signature`, `POST …/offline-confirmation`) with `status: VERIFIED` | `evidence` | Position of the record just sealed, which was the head when it was returned |

## Exports

`GET /v1/authorizations/{id}/evidence` returns one `AUTHORIZATION` record with `credentialEnrolment`, the `CREDENTIAL_ENROLLED` record its `enrolmentEvidenceHash` names, so the export verifies on its own. The verifier requires it: a single schema 3 authorization export without `credentialEnrolment` is `INVALID` (`the enrolment record of the signing credential is missing`), so removing the field cannot skip the key provenance check.

`GET /v1/nexus-identities/{nexusId}/evidence` returns `{ nexusId, records, head, evidencePublicKeyPem, evidencePublicKeys }`, records in `chainSequence` order. It is paged with `after` (a `chainSequence`) and `limit` (at most 1000). The verifier checks positions from 1, so a chain is verified from one file whose `records` hold every page.

Both responses include `evidencePublicKeyPem` (the current HSM key) and `evidencePublicKeys` (`{ sealKeyId: PEM }` for the current key and every retired key).

## Verification rules

| Check | Rule |
|---|---|
| Record hash | `evidenceHash = hex(SHA-256(canonicalJson(sealedPayload)))` |
| HSM seal | ECDSA P-256 / SHA-256 over the 32 bytes of `evidenceHash`, DER, verifies with the evidence key whose key ID is `sealKeyId`. Another key that happens to verify is not accepted |
| Metadata | `nexusId`, `previousEvidenceHash`, `recordType`, `chainSequence` (and `authorizationId` for authorizations) outside the payload equal the sealed values; for schema 3 also `credentialId`, `sealKeyId` and `schemaVersion` (a missing field counts as a mismatch). Auth Core applies the same rule to the database columns before using a record |
| Signed bytes (`AUTHORIZATION`) | `SHA-256(signed bytes) = canonicalPayloadHash`, and the bytes name the same `authorization_id`, `nexus_id`, `credential_id` and `transaction_reference` |
| Customer signature (`AUTHORIZATION`) | ECDSA P-256 / SHA-256 over the signed bytes verifies with `credentialPublicKeyPem` (`der`, or `raw` r‖s). Offline confirmations carry an HMAC tag (below) |
| Key provenance (`AUTHORIZATION`) | The `CREDENTIAL_ENROLLED` record whose `evidenceHash` is `enrolmentEvidenceHash` appears earlier in the chain (or is attached to a single-record export), is valid, names the same credential and sealed the same signing key |
| Enrolment content (`CREDENTIAL_ENROLLED`) | Carries the credential ID of the record and a signing public key |
| Recovery content (`RECOVERY_CONFIGURED`) | Carries a recovery public key |
| Numbering | Records are numbered 1, 2, 3 … without gap or duplicate |
| Links | Each record's sealed `previousEvidenceHash` is the `evidenceHash` of the record before it; the first is `null` |
| Head | With an expected head, the record at that `chainSequence` exists and has that `evidenceHash` |

The signed bytes are the protocol v1 object, so the amount, currency, beneficiary and expiry the customer saw can be read directly from them.

A transaction confirmed offline with an 8-digit code ([offline confirmation](device-authentication-and-offline-confirmation.md)) is sealed and chained the same way, with `confirmationMethod: OFFLINE_CODE`, `signatureFormat: hmac`, `signatureAlgorithm: HMAC-SHA256` and the HMAC tag behind the code in `signature`. The record binds the exact bytes the phone displayed, but the code was computed with a key Auth Core also holds, so the customer's part cannot be re-verified by a third party. The verifier checks everything else and counts these records separately (`offline_codes=… (not third-party verifiable)`).

With [offline confirmation v2](offline-confirmation-v2-deferred-signature.md) the record is sealed only when the device's own signature has arrived: `confirmationMethod: OFFLINE_SIGNED`, `signature`/`signatureFormat`/`signatureAlgorithm` are the device's ECDSA signature (verified like `DEVICE_SIGNATURE`), and the payload adds `offlineCodeTag` (base64, 32 bytes), `offlineCodeAcceptedAt` and `deferredSignatureReceivedAt`. Verifiers before this addition report `unknown confirmation method`. `verify-evidence.mjs --reject-offline-code` fails every `OFFLINE_CODE` record.

## Running the verifier

`auth-core/scripts/verify-evidence.mjs` implements these rules with Node.js only and does not import any Auth Core code:

```bash
curl -s -H "Authorization: Bearer $TOKEN" https://nexus-sign.bank.example/v1/nexus-identities/123456789/evidence > chain.json
node scripts/verify-evidence.mjs chain.json --public-keys=evidence-keys.pem --expect-head=7:3f1c…
```

```text
VALID  #1  credential 5d2e… enrolled (ENROLMENT, attestation VERIFIED)
VALID  #2  recovery key configured by credential 5d2e…
…
VALID  #7  9b41…  transfer 125000 (minor units) PLN to [iban=PL61…, name=Jan Kowalski], ref TX-2026-000154, signed at 2026-10-06T10:00:00.000Z
EVIDENCE_VALID records=7 hsm_seal=verified device_signatures=5/5 verified chain=linked head=matched
```

| Option | Use |
|---|---|
| `--public-keys=<file.pem>` | One file with one or more PEM public keys: the current and retired evidence keys, obtained out of band (for example from the HSM key ceremony records). Without it the keys in the export are used, which an audit should not rely on: the script then prints a `WARNING` on standard error, the summary starts with `EVIDENCE_SELF_CONSISTENT` and reports `hsm_seal=verified_with_export_keys`, and the exit code is 3. `--public-key` is accepted as an alias |
| `--expect-head=<chainSequence>:<evidenceHash>` | The head the bank stored from its latest confirmation. Without it (and without `--heads`) the summary says `head=not_checked`, records removed from the end of the chain are not detected, and a chain export exits with 4 |
| `--allow-unchecked-head` | Exit 0 instead of 4 for a chain checked without a head the bank kept, for callers that check the end of the chain themselves |
| `--heads=<file>` | The heads the bank kept from `evidence.appended` webhooks for this NEXUS ID (JSON array, or one JSON object per line). Each must carry a valid HSM seal and be present unchanged in the export; a head past the end of the export reports `records missing at the end of the chain`. The summary then says `heads=<n>_matched`. New (unreleased, planned for 2.0.0) |

The input is either export. The exit code is 0 for evidence valid against the keys given with `--public-keys` (for a chain export, also checked against a head the bank kept), 4 for a chain valid against those keys whose end was not checked, 3 for evidence that is consistent only with the keys inside the export, 1 for invalid evidence (one `INVALID` line per problem) and 2 for a usage error. A chain export with no records is invalid, and so is one that ends before the `head` it names itself (a page of a longer chain, or a truncated file); that `head` comes from the same export, so it does not replace a head the bank kept.

## Key rotation

Each record names its sealing key by `sealKeyId`, so records sealed before and after an HSM key change verify in one chain.

- After a rotation, the public keys of retired evidence keys are configured in `EVIDENCE_RETIRED_PUBLIC_KEYS_PEM` (concatenated PEM blocks). Auth Core publishes them with the current key in `evidencePublicKeys` and uses them for its own [runtime integrity check](#runtime-integrity-check); a credential whose enrolment was sealed with a key Auth Core no longer knows is refused.
- An auditor's `--public-keys` file holds every key the deployment has sealed with.
- `hsmKeyVersion` remains in the metadata as the operator's label; it is not used for verification.

## Runtime integrity check

Auth Core does not trust the database for the keys that decide who the customer is (`auth-core/src/services/credentialIntegrity.ts`). Before a credential's keys are used, they are compared with the credential's sealed `CREDENTIAL_ENROLLED` record (`credentials.enrolment_evidence_id`), after its hash and HSM seal are checked against the known evidence keys:

| Where | On a mismatch |
|---|---|
| Device-signed request (`middleware/mobileAuth.ts`) | 401, as for an unknown credential |
| Signature or offline-code confirmation (`authorizationConfirmation.ts`) | Result `FAILED` with reason `credential_integrity`; nothing is sealed |
| Recovery setup (`POST /v1/mobile/recovery/setup`) | Checked by the request authentication above (401) and again before the registration (403) |

Each refusal is audited as `integrity_violation`. Recovery session creation and completion run the same check on the identity's recovery key against its latest `RECOVERY_CONFIGURED` record, and session creation also compares the salt and iteration count with the sealed ones (409 `RECOVERY_INTEGRITY`). Verified enrolment records are cached by evidence ID in the process; they cannot change, because the table is append-only and the content is covered by the seal.

The database trigger of migration 017 also makes a credential's keys immutable and its enrolment reference settable only once ([state machines](../architecture/state-machines.md)).

## Records from before schema 3

| Records | Verification |
|---|---|
| Schema 2 (migrations 009 to 012) | Hash, seal and device signature are verified as before; the seal is accepted with any of the given keys, since the record does not name one. Migration 013 numbered existing records per NEXUS ID by `created_at`; that number is metadata, not sealed. A schema 2 authorization has no `enrolmentEvidenceHash`, so its key provenance cannot be checked. The summary counts them as `legacy_records=… (sealed before schema 3: no key provenance)` |
| Schema 1 (before migration 009) | No sealed payload. The verifier reports `unsupported or missing sealed payload` and the chain does not verify |

The first schema 3 record of a chain links to the last schema 2 record as usual.

### Baseline sealing of existing credentials

Credentials registered before 2.0 have no sealed enrolment, and Auth Core refuses to use their keys until they have one. Once, after migration 013 and before serving traffic:

```bash
node dist/cli/sealCredentialBaseline.js
```

For every `ACTIVE` credential without an enrolment record, the command seals a `CREDENTIAL_ENROLLED` record with reason `BASELINE`, the keys the database holds at that moment, the stored attestation status and material `{ "format": "none", "note": "enrolled before evidence schema 3" }`, and records the audit event `credential_baseline_sealed`. It prints one line per credential and is safe to run again; already sealed credentials are skipped.

A baseline record states what the database held when the command ran. It does not prove how the keys got there. Run it in the controlled upgrade window and keep its output with the change record.

## Storage guarantees and limits

- Raw audio and video are never part of evidence; only the provider reference and the SHA-256 of the provider assertion are stored.
- An append-only table, the unique indexes and the database roles protect against application defects and the application's database role. A database owner or superuser can disable the triggers. The seals, the numbering and the head the bank holds make a later change, removal or substitution detectable, not impossible. Banks that need more export records to WORM storage or a SIEM.
- A verifier given no expected head, or an outdated one, cannot detect records removed after that head.
