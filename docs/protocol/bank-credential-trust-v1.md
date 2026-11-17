# Bank credential trust v1

Status: unreleased, planned for 2.0.0 (current version 2.0.0-rc.2). Implemented in `auth-core/scripts/lib/bankTrust.mjs`, the tools `scripts/bank-trust-statement.mjs` and `scripts/bank-execution-check.mjs`, and the SDK call `signingKeyFingerprint()`. Vectors: `auth-core/test-vectors/bank-trust-v1.json`.

## Why

Auth Core seals every enrolment and confirmation with the evidence key in its HSM, and checks each confirmation against the sealed enrolment of the signing key. Those checks protect against the database and against anyone who cannot use the HSM. They do not protect against Auth Core itself. A compromised Auth Core runs its own code with its database and its HSM session, so it can:

1. register a new credential (no bank token needed, a replacement authorization invented, attestation reported as verified), or replace the key of an existing credential;
2. seal that enrolment with the real evidence key;
3. let the attacker sign confirmations with the new key;
4. report `VERIFIED`, `confirmed: true` and accept the commit request (202);
5. export evidence that the independent verifier accepts with the pinned evidence keys.

All five are reproduced in `auth-core/test/integration/bank-trust-compromise.test.mjs` (Auth Core's compiled code on SoftHSM). A valid seal and a valid device signature only show that Auth Core sealed a record and that some key signed it. Whether the bank enrolled that device for that customer is a separate fact, and only the bank can establish it. So the bank decides from its own records.

| Property | Who establishes it | How |
|---|---|---|
| The device signature is cryptographically valid | anyone | ECDSA over the signed bytes (verifier) |
| The evidence is intact | anyone with the pinned evidence keys | hash, HSM seal, chain, metadata (verifier) |
| The device registration is genuine | **the bank** | its app reported this key's fingerprint for this customer through the bank's own channel |
| The bank trusts this device | **the bank** | a credential approval signed with the bank's trust key, not revoked |
| This transaction may be executed | **the bank** | the decision below, with the terms the bank asked for |

## Statements

The bank signs two kinds of statement with its **trust key**: an ECDSA P-256 key the bank generates and keeps, in its own HSM in production. Auth Core never holds it. The public half is the only trust input the check needs besides the pinned evidence keys.

```json
{ "type": "NEXUS_CREDENTIAL_APPROVAL", "version": 1, "nexusId": "123456789",
  "credentialId": "3f2b8c1e-…", "signingKeySha256": "<hex>", "reference": "<bank's reference>",
  "approvedAt": "2026-10-19T10:00:00.000Z", "bankKeyId": "<hex>" }

{ "type": "NEXUS_CREDENTIAL_REVOCATION", "version": 1, "nexusId": "123456789",
  "credentialId": "3f2b8c1e-…", "reason": "lost", "revokedAt": "…", "bankKeyId": "<hex>" }
```

- `signingKeySha256` and `bankKeyId` are the lowercase hex SHA-256 of a key's DER SubjectPublicKeyInfo.
- Signature: ECDSA P-256 with SHA-256, DER encoded, base64, over `canonicalJson(statement)`. The statement includes `bankKeyId`, and `canonicalJson` is the evidence format's encoding.
- Stored entry: `{ "statement": {…}, "signature": "<base64>" }`. The registry is the bank's list of entries: a JSON array or JSON lines.
- A revocation is final: the credential is never accepted again, whatever its approval says. A new device gets a new credential ID and a new approval.

## When the bank writes them

| Event | The app sends | The bank backend checks | Then writes |
|---|---|---|---|
| Enrolment (`bootstrap()`) | `credentialId`, `signingKeyFingerprint()`, over its own authenticated session with the customer | `GET /v1/credentials/{id}`: same `nexusId`, `ACTIVE`, attestation as required. The credential's `CREDENTIAL_ENROLLED` record in `GET /v1/nexus-identities/{nexusId}/evidence`, verified with the pinned evidence keys, seals a signing key with this fingerprint. | approval |
| Replacement | the same, for the new credential | the same; the bank itself issued the replacement token | approval of the new credential, revocation of the replaced one(s) |
| Recovery (`recoverIdentity`) | the same, for the recovered credential | the same; the bank itself opened the recovery session | approval of the new credential, revocation of every earlier one |
| Lost device, closure | — | — | revocation, then `POST /v1/credentials/{id}/revoke` at Auth Core |

The fingerprint comes from the device. The SDK computes it from the key in the Keystore or Secure Enclave, not from an Auth Core response. If Auth Core substitutes the key at enrolment, the fingerprint in the enrolment record differs from the one the app reported, and the bank does not approve.

## The decision before execution

`bankExecutionDecision({ evidence, evidenceKeys, bankTrustKeys, registry, expected, chain?, expectedHead?, heads? })`, or the command line:

```bash
node scripts/bank-execution-check.mjs authorization-evidence.json \
  --public-keys=pinned-evidence-keys.pem --bank-trust-keys=bank-trust-keys.pem \
  --registry=bank-statements.jsonl --expect=expected-terms.json \
  [--chain=chain.json --expect-head=<sequence>:<evidenceHash> --heads=heads.jsonl]
# Exit 0: execute; 1: do not execute (reasons on stderr); 2: usage error
```

The bank executes only when every one of these holds:

1. **Pinned evidence keys.** The evidence verifies (hash, HSM seal, metadata, device signature, enrolment link) with the keys the bank recorded at the key ceremony, never with the keys in the export. Without pinned keys the answer is no. Code-only offline records are refused.
2. **Terms.** `authorization_id`, `nexus_id`, `transaction_reference`, `amount_minor`, `currency`, `beneficiary` (and `operation_type` if given) in the signed bytes equal what the bank's own system asked for.
3. **Approval.** A bank-signed approval exists for this `nexusId` and `credentialId` with the fingerprint of the key that signed (`credentialPublicKeyPem`), and of the key in the attached enrolment record.
4. **No revocation** for the credential in the bank's registry. Auth Core's state is not consulted.
5. **Registry intact.** Every registry entry is well formed and verifies with a bank trust key. Any entry that does not stops the decision: the registry is the bank's own, so a bad entry means it was changed.
6. **With the chain export** (recommended):
   - the chain verifies with the pinned keys;
   - every `CREDENTIAL_ENROLLED` record in it is approved by the bank, which reveals registrations the bank never approved even when they are not used for this payment;
   - the authorization record is in the chain;
   - the heads the bank kept (`--expect-head`, `--heads`) are present and unchanged.

`VERIFIED`, `confirmed: true`, the 202 for `bank-commit-request` and webhooks remain preconditions and signals, not inputs to this decision.

## What is detected, and what is not

| Situation | Detected by |
|---|---|
| Registration not approved by the bank (used, or only present in the chain) | 3, 6 |
| Key of an approved credential substituted | 3 (fingerprint differs) |
| Credential revoked or replaced at the bank, still active at Auth Core | 4 |
| Approval forged (not signed by a bank trust key), altered, or for another customer | 3, 5 |
| Evidence sealed with a key the bank did not pin, or no pinned keys | 1 |
| A kept chain head changed, or the chain cut before it | 6 (`--expect-head`, `--heads`) |
| Terms other than the bank asked for, signed by an approved device | 2 |
| **Records removed after the last head the bank kept** | **not detectable**: without a later independent head the shortened chain is consistent in itself. Keep a head for every confirmation (`evidence.appended`). |

## Limits

- The property holds only if the bank keeps its trust key, its registry, its pinned evidence keys and its heads outside Auth Core's reach, runs the check in its own systems, and takes the fingerprint from its own app channel. A compromised bank backend or bank app is outside this protocol.
- A compromised Auth Core can still refuse service: decline confirmations, delay, or block commits. It can also show the customer's device an authorization the bank did not create, but such a signature does not pass rule 2.
- The device's attestation is checked by Auth Core only. A bank that wants hardware provenance it can verify itself has to check the attestation chain on its own. That is not part of v1.
- The customer's own device, if compromised, signs with an approved key. This protocol does not address that.
