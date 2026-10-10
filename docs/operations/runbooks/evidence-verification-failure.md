# Evidence verification failure

Two checks protect the evidence chain:

- **Offline:** `auth-core/scripts/verify-evidence.mjs` checks an evidence export without Auth Core: the HSM seals, the hash chain and its numbering, the provenance of every device key (its sealed enrolment), the customer's device signature, and, with `--expect-head`, that the chain still reaches the head the bank received.
- **At runtime:** before a credential's keys are used, Auth Core compares them with the credential's sealed `CREDENTIAL_ENROLLED` record, and before a recovery it checks the identity's `RECOVERY_CONFIGURED` record (`src/services/credentialIntegrity.ts`, `recoveryService.ts`). A failure is refused and recorded as the audit event `integrity_violation`.

The record format and rules are in [evidence format](../../protocol/evidence-format.md).

## Running the offline check

A chain export returns at most 1000 records per call (`after`, `limit`). The verifier needs the whole chain from record 1 in one file; collect the pages first:

```sh
after=0; : > records.jsonl
while :; do
  curl -sS -H "Authorization: Bearer $TOKEN" \
    "$AUTH_CORE/v1/nexus-identities/$NEXUS_ID/evidence?after=$after&limit=1000" > page.json
  n=$(jq '.records | length' page.json)
  jq -c '.records[]' page.json >> records.jsonl
  [ "$n" -lt 1000 ] && break
  after=$(jq '.records[-1].chainSequence' page.json)
done
jq -s --slurpfile p page.json '{nexusId: $p[0].nexusId, records: ., head: $p[0].head, evidencePublicKeys: $p[0].evidencePublicKeys}' \
  records.jsonl > chain.json
```

Then, from a checkout of the release (`scripts/` is not in the image):

```sh
cd auth-core
node scripts/verify-evidence.mjs chain.json --public-keys=evidence-keys.pem --expect-head=42:3f9a...e1
curl -sS -H "Authorization: Bearer $TOKEN" "$AUTH_CORE/v1/authorizations/$AUTHORIZATION_ID/evidence" > record.json
node scripts/verify-evidence.mjs record.json --public-keys=evidence-keys.pem
```

| Option | Meaning |
|---|---|
| `--public-keys=<file>` | One or more PEM public keys in one file: every evidence key the deployment has used. Schema 3 records are checked with the key their `sealKeyId` names; older records with any key in the file. Without the option the script uses `evidencePublicKeys` (or `evidencePublicKeyPem`) from the export, which Auth Core supplied; it then prints `WARNING  seals were checked against the public keys inside the export; ...` on standard error, reports `EVIDENCE_SELF_CONSISTENT ... hsm_seal=verified_with_export_keys` and exits with code 3. For audits, pass the keys from the key ceremony record. `--public-key` is accepted as an alias. |
| `--expect-head=<chainSequence>:<evidenceHash>` | Chain exports only. The head the bank stored: the `evidence` of its latest confirmation result or authorization, or the identity's `evidenceHead`. Records removed from the end of the chain are reported. Without it the script prints `head=not_checked`, and a truncated chain verifies. |

| Exit code | Output | Meaning |
|---|---|---|
| 0 | One `VALID  #<chainSequence>  ...` line per record, then `EVIDENCE_VALID records=... hsm_seal=verified device_signatures=<n>/<m> verified`, plus `chain=linked` and `head=matched` or `head=not_checked` for a chain | All checks passed against the keys given with `--public-keys` |
| 3 | The same lines, but `EVIDENCE_SELF_CONSISTENT ... hsm_seal=verified_with_export_keys`, and a `WARNING` on standard error | All checks passed, but only against the keys inside the export: not an independent verification |
| 1 | `INVALID  <record>: <problem>` per problem, on standard error | At least one check failed |
| 2 | Usage text, or `No evidence public key: pass --public-keys=<file.pem>` | Wrong arguments or no key |

`<record>` is the authorization ID, or `<recordType>#<chainSequence>` for enrolment and recovery records. `offline_codes=N (not third-party verifiable)` in the summary is expected for records confirmed with an offline code: their sealed tag is an HMAC that only Auth Core and the device can compute. `legacy_records=N (sealed before schema 3: no key provenance)` counts records sealed by 1.4 or earlier.

## Symptoms

- `INVALID` lines from the script, or an auditor reports that a record or chain does not verify.
- `integrity_violation` events in `audit_logs`; customers whose devices receive 401 on every request, confirmations returning `FAILED` with `reason: credential_integrity`, recovery setup 403, or recovery session creation or completion 409 `RECOVERY_INTEGRITY`.

## Impact

A record that does not verify cannot serve as proof of the authorization in a dispute until the cause is known. An `integrity_violation` blocks the affected customer: the credential's keys, or the identity's recovery key, are not used while the database disagrees with the sealed record. An unexplained failure of either kind is a possible integrity incident; follow [incident response](../incident-response.md).

## Diagnosis

### Offline check problems

| Problem | Typical cause |
|---|---|
| `unsupported or missing sealed payload` | Record sealed before migration 009; it has no `sealed_payload` and cannot be verified offline ([migrations](../../../auth-core/migrations/README.md)). |
| `HSM seal does not verify with the evidence key it names` | The key file lacks the key of the record's `sealKeyId` (most common after a key rotation), or `evidenceHash` or `hsmSignature` were changed |
| `evidence hash does not match the sealed payload` | The sealed payload differs from what was sealed |
| `record metadata does not match the sealed payload`, `record type differs between record and payload`, `chain position differs between record and payload`, `previousEvidenceHash differs between record and payload` | A column outside the payload differs from the sealed value |
| `chain position <n> where <m> was expected (records missing or duplicated)` | A record is missing inside the chain, or the export does not start at record 1 (an incomplete page collection) |
| `chain broken (expected previous ...)` | A record is missing or substituted, or records are out of order |
| `records missing at the end of the chain: the bank's head is record <n>, the export ends at <m>` | Records after the bank's head were removed, or the database was restored to a point before that head |
| `record <n> differs from the head the bank received` | The record at the bank's head position was replaced |
| `the enrolment of the signing credential is not earlier in the chain`, `the device key differs from the key sealed at enrolment`, `the enrolment record of the signing credential is missing`, `the attached enrolment is not the one the authorization names` | The key that signed an authorization is not the key sealed when the credential was enrolled |
| `signed bytes do not match canonicalPayloadHash` | The device-signed bytes in the payload are not the bytes behind the hash |
| `signed bytes name a different authorization, identity, credential or reference` | The signed bytes belong to another transaction |
| `device signature does not verify over the signed bytes` | The device signature does not match the sealed bytes and device key |
| `offline confirmation record does not carry an HMAC tag` | `OFFLINE_CODE` record without `signatureFormat: hmac` and `HMAC-SHA256` |

Seal failures and keys. List the keys used in the chain and compare with the key file (key ID of a PEM file: `openssl pkey -pubin -in key.pem -outform DER | sha256sum`):

```sql
SELECT seal_key_id, hsm_key_version, count(*), min(chain_sequence), max(chain_sequence)
FROM evidence_records
WHERE nexus_id = :'nexus_id'
GROUP BY seal_key_id, hsm_key_version;
```

Compare the export with the database:

```sql
SELECT chain_sequence, record_type, evidence_id, authorization_id, credential_id, evidence_hash, previous_evidence_hash,
       seal_key_id, schema_version, created_at
FROM evidence_records
WHERE nexus_id = :'nexus_id'
ORDER BY chain_sequence;
```

A difference between the exported file and the database points at the transfer or the file; the same values in both point at the stored data. A head mismatch with the database identical to the export means the database no longer contains what it contained when the bank received the head.

### Runtime integrity violations

```sql
SELECT "timestamp", nexus_id, client_id, actor, ip_address, details
FROM audit_logs
WHERE event_type = 'integrity_violation'
ORDER BY "timestamp" DESC
LIMIT 50;
```

`details.reason` is one of:

| Reason | Meaning |
|---|---|
| `the credential has no sealed enrolment record` | `enrolment_evidence_id` is empty. Expected only if `sealCredentialBaseline` was not run after the upgrade ([upgrade](../upgrade-2.0.md)) |
| `the sealed enrolment record does not exist`, `the referenced record is not a credential enrolment`, `the sealed enrolment belongs to another credential` | `enrolment_evidence_id` points at the wrong record |
| `the record was sealed with an unknown evidence key` | The record's key is neither the current HSM key nor in `EVIDENCE_RETIRED_PUBLIC_KEYS_PEM`; after a rotation, see [key rotation](key-rotation.md) |
| `the record content does not match its evidence hash`, `the HSM seal does not verify`, `the record is not schema 3` | The sealed record itself was changed |
| `the credential keys differ from the sealed enrolment` | A key column of `credentials` was changed |
| `recovery key: ...` | The same checks for the identity's recovery key and wrapped key |

Compare the credential with its sealed enrolment:

```sql
SELECT c.credential_id, c.state, c.public_key_pem, c.auth_public_key_pem, c.offline_public_key_pem,
       e.sealed_payload->'keys' AS sealed_keys, e.seal_key_id, e.chain_sequence
FROM credentials c LEFT JOIN evidence_records e ON e.evidence_id = c.enrolment_evidence_id
WHERE c.credential_id = :'credential_id';
```

### Database protections

Who Auth Core connects as, and who owns the tables (expected: `nexus_app` and `nexus_owner`):

```sql
SELECT current_user;
SELECT tablename, tableowner FROM pg_tables WHERE tablename IN ('evidence_records', 'audit_logs', 'credentials', 'nexus_identities');
```

Triggers (expected: all present with `tgenabled = 'O'`):

```sql
SELECT tgrelid::regclass AS table_name, tgname, tgenabled
FROM pg_trigger
WHERE tgrelid IN ('evidence_records'::regclass, 'audit_logs'::regclass, 'credentials'::regclass,
                  'nexus_identities'::regclass, 'authorization_requests'::regclass)
  AND NOT tgisinternal
ORDER BY 1, 2;
```

`evidence_records`: `trg_evidence_append_only`, `trg_evidence_no_truncate`; `audit_logs`: `audit_logs_no_update`, `audit_logs_no_truncate`; `credentials`: `credential_lifecycle`; `nexus_identities`: `identity_lifecycle`; `authorization_requests`: `authorization_lifecycle`.

With `scripts/db/roles.sql` applied, `nexus_app` owns no table and cannot disable or replace these triggers, set `session_replication_role` or truncate. A superuser, the provider's admin role and members of `nexus_owner` can; review `pgaudit` or the provider's audit log for `ALTER TABLE ... DISABLE TRIGGER`, `session_replication_role`, `DROP TRIGGER`, `CREATE OR REPLACE FUNCTION` and for writes to `evidence_records`, `credentials` and `nexus_identities` outside the application's sessions.

## Resolution

1. Missing key: rerun with a key file that contains every evidence public key. If a key is not on record, obtain it from the HSM team; for a runtime failure after a rotation, add it to `EVIDENCE_RETIRED_PUBLIC_KEYS_PEM` and restart.
2. Incomplete export: collect all pages and rerun.
3. Missing baseline after the upgrade: run `node dist/cli/sealCredentialBaseline.js` once. It seals only credentials without an enrolment record.
4. Pre-009 records: no action is possible in Auth Core. Report them as sealed but not offline-verifiable.
5. Any other problem, a head mismatch, or an `integrity_violation` with a reason other than the three above: treat as an integrity incident ([incident response](../incident-response.md#evidence-or-database-tampering)). Preserve the export, a database snapshot and the logs; do not modify `evidence_records` or the affected `credentials` row. Compare with the bank's stored heads and its WORM or SIEM copy of the evidence. Suspend the affected identity while the cause is open; the customer enrols a new device after re-identification once it is resolved.

## Follow-up

- Record the public key of every evidence key in the key ceremony record; see [key rotation](key-rotation.md).
- Banks store the chain head of every confirmation; schedule periodic verification of a sample of NEXUS IDs with `--expect-head` and keep the script output with the audit records.
- Alert on every `integrity_violation` event through the bank's SIEM or SQL exporter; Auth Core exports no metric for it ([incident response](../incident-response.md#detection)).
