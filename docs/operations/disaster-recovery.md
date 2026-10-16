# Disaster recovery

How to restore Auth Core after the loss of a component, and what each loss means for customers, banks and evidence. Recovery objectives are the bank's decision; Auth Core does not define them. Fill in before go-live:

| Item | Value |
|---|---|
| Recovery time objective (RTO) | `<set by the bank>` |
| Recovery point objective (RPO) for PostgreSQL | `<set by the bank>` |
| PostgreSQL backup and point-in-time recovery method | `<provider / tooling>` |
| HSM key backup and restore procedure | `<HSM vendor / bank HSM team>` |
| Secondary site | `<location>` |
| Last DR test | `<date, result>` |

## Where state lives

| State | Store | Backed up by | Needed for recovery |
|---|---|---|---|
| Identities, credentials, authorizations, evidence, audit, bank clients, admin accounts, webhook and push outboxes | PostgreSQL | Database backups and PITR | Yes |
| Bank and mobile tokens, admin sessions, device nonces, login throttles, recovery setup salts | Redis | Not to be restored ([Redis](#redis)) | No |
| Evidence signing key | HSM | HSM vendor's backup procedure | The private key for sealing; the public keys for verification |
| Evidence public keys of every key used | Key ceremony record | Bank | Yes, for verification |
| Master keys, PKCS#11 PIN, attestation and push provider credentials | Secrets manager | Secrets manager | Yes; data encrypted under a lost master key cannot be recovered |
| Configuration | Deployment repository | Bank | Yes |
| Evidence chain heads (latest `chainSequence` and `evidenceHash` per identity) | Each bank's own systems | Bank | Yes, to detect lost or altered evidence |
| Evidence and audit copies | Bank WORM or SIEM | Bank | For comparison |
| Android attestation status list | File | Not needed | Downloaded again |

Auth Core processes hold no durable state; a lost pod is replaced by redeploying.

## Redis

### Consequences of a Redis loss

When Auth Core starts with an empty Redis (a new instance, or after a failure without persistence):

| Lost | Effect | Recovery |
|---|---|---|
| Bank access tokens | Bank calls receive 401 | Bank backends request new tokens |
| BOOTSTRAP tokens | Enrolments in progress receive 401 | Apps request new tokens from the bank backend |
| Admin sessions | Admins are logged out | Log in again (password and TOTP) |
| Recovery setup salts | A recovery setup in progress fails with 409 `RECOVERY_SETUP_EXPIRED` | The SDK requests new parameters |
| Login throttle counters | Failure counts for `/oauth/token` and admin login start again from zero | None |
| Device request nonces | A device-signed request captured before the loss can be accepted once more while its timestamp is within `DEVICE_REQUEST_MAX_SKEW_SECONDS` (default 300 s) of server time | The exposure ends `DEVICE_REQUEST_MAX_SKEW_SECONDS` after the loss. A bank that wants to exclude it keeps Auth Core out of routing for that time after Redis is back |

Nothing durable is lost: authorizations, credentials and evidence are in PostgreSQL.

### Do not restore Redis or fail over to a lagging replica

Restoring a Redis snapshot, or promoting an asynchronous replica that missed recent writes, brings back state that was deliberately removed (NXS-021):

- consumed BOOTSTRAP tokens, which enrol a device again, and with a stored `replacement` replace the customer's current device;
- device request nonces that were recorded after the snapshot are missing, so those requests can be replayed;
- bank access tokens revoked by `registerClient` after the snapshot;
- admin sessions ended by logout after the snapshot (sessions of accounts reset with `createAdminUser` stay ended, because the session version is checked in PostgreSQL).

After a Redis incident, start with an empty Redis. If a lagging replica was promoted, empty it (`FLUSHALL`) and accept the consequences in the table above. Deployment requirements are in [deployment](deployment.md#redis).

## Database restore

A restore to a point before the failure loses everything written after that point. The steps below restore service and then establish which customer-visible facts were lost.

### Restore

1. Stop Auth Core (scale to zero or remove it from routing). Record the time of the failure and the chosen restore point.
2. Restore PostgreSQL to the restore point with the provider's or DBA's tooling.
3. Roles are cluster objects and may not be part of a database backup. Re-create them if needed and apply `scripts/db/roles.sql` ([database roles](deployment.md#database-roles)); enable the `nexus_app` login.
4. Check the schema level and the protections: the 2.0 columns exist (for example `evidence_records.chain_sequence`, `admin_approvals`), and the triggers listed in [evidence verification failure](runbooks/evidence-verification-failure.md#database-protections) are present and enabled. If the backup predates an upgrade, apply the missing migrations ([migrations](../../auth-core/migrations/README.md)).
5. Check that every non-revoked credential has an enrolment record; run `node dist/cli/sealCredentialBaseline.js` only if the backup predates the 2.0 upgrade:

   ```sql
   SELECT count(*) FROM credentials WHERE state <> 'REVOKED' AND enrolment_evidence_id IS NULL;
   ```

6. Start Auth Core with an empty Redis. Confirm `/readyz` 200 on every pod. Keep bank traffic closed until the next section is done, or reopen it with the banks' agreement.

### Re-apply what the restore undid

Changes made after the restore point are gone from the database, including protective ones. Rebuild them from the banks' records, the webhook receivers' logs, and the audit records exported to the SIEM (the restored `audit_logs` ends at the restore point):

| Lost change | Consequence after restore | Action |
|---|---|---|
| Credential revocations, identity suspensions and revocations | The credential or identity is active again | Repeat them before reopening traffic |
| Client secret rotations (`registerClient`) and fingerprint changes (`setClientCertificates`, `registerClient --mtls-cert-sha256`) | The previous client secret, webhook secret and fingerprints are valid again | Run `registerClient` again for clients whose secrets were rotated and hand over the new secrets; run `setClientCertificates` again for clients whose fingerprints changed |
| Admin account resets and new accounts (`createAdminUser`) | Previous passwords and TOTP secrets are valid again; new accounts are missing | Run `createAdminUser` again |
| Device enrolments and replacements | The new device's credential does not exist: its requests receive 401. A replaced device's credential is active again | Revoke the reactivated old credentials; customers enrol the new devices again after re-identification |
| Recovery setups (`recovery.configured` webhooks after the restore point) | The identity has the previous recovery key or none; the phrase set up later does not open it | Customers set up recovery again |
| Completed recoveries (`identity.recovered`) | The old credential is active again and the recovered device unknown | Revoke the old credential; the customer enrols again |
| Confirmed authorizations | Authorizations confirmed after the restore point are `PENDING_USER` again or missing, and their evidence is gone | See [evidence](#evidence-after-a-restore) |
| Bank commit requests and results | The bank transaction state is earlier than the bank's ledger | Reconcile with `GET /v1/authorizations/{id}/bank-transaction`; repeat the calls where the authorization is still `VERIFIED` |
| Webhook deliveries | Events written after the restore point are lost; events written before it and delivered after it may be delivered again | Receivers deduplicate on `eventId` |

### Evidence after a restore

Each bank holds the chain head it received with every confirmation, identity read and chain export. After a restore:

1. For every identity for which a bank holds a head, export the chain (all pages) and run the verifier with that head:

   ```sh
   node scripts/verify-evidence.mjs chain.json --public-keys=evidence-keys.pem --expect-head=<chainSequence>:<evidenceHash>
   ```

2. Interpret the result:

   | Result | Meaning |
   |---|---|
   | `EVIDENCE_VALID ... head=matched` | Nothing of this chain was lost |
   | `records missing at the end of the chain: the bank's head is record <n>, the export ends at <m>` | Records `m+1` to `n` were sealed after the restore point and are lost from Auth Core. The bank's own copy of those results (authorization IDs, verification results, heads) is the remaining record |
   | `record <n> differs from the head the bank received` | A record was sealed at that position after the restore; investigate as a possible integrity problem ([incident response](incident-response.md#evidence-or-database-tampering)) |

3. Once traffic resumes, new records are numbered from the restored head. A position the bank already holds from before the restore then carries a different record, so later checks against the old head report `differs from the head the bank received`. Record the gap with the bank before traffic resumes: for each affected identity, the lost range and the restored head, which the bank stores as its new reference.

4. Authorizations whose confirmation was lost: the bank decides, per transaction, whether to rely on its own record of the confirmation or to ask the customer again with a new authorization. Commit requests for them fail, because they are no longer `VERIFIED` in Auth Core.

## HSM

| Event | Recovery |
|---|---|
| HSM unavailable | [HSM unavailable](runbooks/hsm-unavailable.md) |
| Evidence private key lost, public key known | Restore it from the HSM backup if one exists. Otherwise generate a new key and rotate ([key rotation](runbooks/key-rotation.md#evidence-sealing-key)), listing the lost key's public key in `EVIDENCE_RETIRED_PUBLIC_KEYS_PEM`. Existing records and credentials stay verifiable, because verification needs only the public key |
| Evidence public key of a former key not on record | Every export carries `evidencePublicKeys`; the HSM team may also hold it. Without it, records sealed with that key cannot be verified offline and credentials sealed with it fail the runtime check |
| Evidence key compromised | [Incident response](incident-response.md#hsm-evidence-key-compromised) |

## Secrets manager

A lost master key cannot be recovered from Auth Core. The data it encrypted is lost:

| Key | Lost data | Recovery |
|---|---|---|
| `WEBHOOK_SECRET_ENCRYPTION_KEY` | Webhook signing secrets | New key; re-register every client with a webhook |
| `DEVICE_SECRET_ENCRYPTION_KEY` | Offline confirmation keys, push keys | New key; devices enrol again for offline confirmation and register for push again |
| `ADMIN_SECRET_ENCRYPTION_KEY` | Admin TOTP secrets | New key; re-provision every admin |

Procedures: [key rotation](runbooks/key-rotation.md). The PKCS#11 PIN, the attestation credentials and the push provider credentials are reissued by their owners (HSM team, Apple, Google).

## Site loss

Restore in this order: secrets and configuration, HSM access, PostgreSQL ([database restore](#database-restore)), an empty Redis, Auth Core, the gateway with its client certificate verification and fingerprint header, the Android status list job. Then follow the evidence and re-apply steps above for the data written after the restore point.

## Testing

Run a DR test before go-live and at the interval set by the bank: `<interval>`. The test restores a production-like database to a point in time, runs the [restore](#restore) steps, verifies a sample of chains against bank-held heads, and runs `scripts/e2e-smoke.mjs`. Record the measured restore time against the RTO.
