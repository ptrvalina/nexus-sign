# Incident response

Procedures for security incidents that involve Auth Core. They use only what the system provides: audit events, evidence chain verification, credential and identity actions, client and admin credential rotation, and HSM key rotation. They complement, and do not replace, the bank's incident management process, which decides on classification, notification and communication.

Fill in before go-live:

| Item | Value |
|---|---|
| Incident manager on call | `<name / rota>` |
| Bank security operations contact | `<contact>` |
| HSM team contact | `<contact>` |
| Database administration contact | `<contact>` |
| Contacts at each bank client (technical, security) | `<per client>` |
| Location of the key ceremony record (evidence public keys) | `<location>` |
| Where each bank keeps its evidence chain heads | `<per client>` |
| Regulatory notification deadlines | `<set by the bank's compliance function>` |

## Detection

Auth Core exports no metrics for security events; they are rows in `audit_logs`, collected by the bank's SIEM or SQL exporter. `audit_logs` is append-only (migration 016) and has these columns:

| Column | Content |
|---|---|
| `event_id`, `timestamp`, `event_type` | Event identity, time, type (`AuditEventType` in `src/types/index.ts`) |
| `nexus_id`, `bank_customer_id` | Affected identity and bank customer reference, when known |
| `client_id` | Bank the event belongs to (from the request, or derived from `nexus_id`) |
| `actor` | `bank:<clientId>`, `device:<credentialId>`, `device-enrolment:<nexusId>` (BOOTSTRAP token), `admin:<username>`, `cli:sealCredentialBaseline`; for an approved admin action `admin:<approver> (requested by admin:<requester>)` |
| `ip_address`, `user_agent` | Source of the request (the client address behind the trusted gateway) |
| `details` | Event-specific JSON |

Events to alert on:

| Event | Meaning | Alert |
|---|---|---|
| `integrity_violation` | A credential's keys or an identity's recovery key differ from the sealed record, or the record does not verify | Every occurrence |
| `bank_certificate_mismatch` | A token request (`details.stage = token`) or bank API call (`stage = api`) with a client certificate not registered for the client; `details.certificateSha256` | Every occurrence |
| `admin_login_failed` | `details.reason`: `unknown_account`, `account_disabled`, `wrong_password`, `wrong_or_reused_totp`, `totp_missing`, `totp_not_enrolled` | Bursts; any `wrong_or_reused_totp` after a correct password |
| `oauth_token_rejected` | Wrong client secret; `details.claimedClientId` (unverified, so `client_id` is empty) | Bursts |
| `recovery_failed`, `recovery_locked` | Failed recovery proofs; identity locked after 10 in 24 hours | Every `recovery_locked`; any `recovery_failed` on protocol 2 |
| `credential_replacement_authorized`, `credential_replaced` | A bank issued a replacement token; a device was replaced | Volume per bank above its normal rate |
| `admin_approval_requested`, `admin_approval_granted`, `admin_approval_rejected` | Four-eyes revocation and reactivation | Review daily |
| `admin_identity_viewed`, `admin_audit_log_viewed` | Admin reads of personal data | Unusual volume per account |
| `recovery_setup_rejected` | A recovery setup not signed by the device signing key | Every occurrence |

Further signals: `INVALID` from `scripts/verify-evidence.mjs`, in particular a head mismatch; `Production security posture is not acceptable` at startup; changes to triggers or roles in the database audit log.

## First steps for every incident

1. Open an incident record with the bank; note the time of detection in UTC.
2. Preserve state before changing it:
   - export the relevant audit rows (as `nexus_audit_reader`) with `event_id`, `timestamp`, `actor`, `ip_address`, `details`;
   - take a database snapshot through the provider or DBA, labelled with the incident;
   - keep the Auth Core and gateway logs for the period;
   - for affected identities, export the evidence chain (all pages) and run the verifier with the bank's stored head ([evidence verification failure](runbooks/evidence-verification-failure.md)).
3. Do not modify `evidence_records`, `audit_logs` or the affected `credentials` rows. Containment uses the actions below.

## Containment actions

| Action | How | Effect | Reversible |
|---|---|---|---|
| Revoke one device credential | Bank backend: `POST /v1/credentials/{id}/revoke` | Credential `REVOKED`, its pending authorizations cancelled | No |
| Suspend an identity | Admin console, one operator: `POST /admin/api/identities/{nexusId}/suspend` | All pending authorizations cancelled; mobile requests, new authorizations, confirmations, enrolment and recovery refused | Yes, by reactivation with four-eyes approval |
| Revoke an identity | Admin console, two admins | Identity and all its credentials revoked | No |
| Rotate a bank client's secrets | `node dist/cli/registerClient.js <clientId> <webhookUrl> --push-mode=<mode> [--mtls-cert-sha256=...]` | New client secret (and webhook secret), all existing access tokens of the client revoked | New secrets only |
| Replace a bank client's certificate fingerprints | `node dist/cli/setClientCertificates.js <clientId> <hex>[,<hex>]` listing only the trusted fingerprints | Tokens issued and accepted only with those certificates; every bank call is checked again, so existing tokens presented with another certificate are refused. Secrets are not rotated | Yes |
| Disable a bank client | Database change: `UPDATE bank_clients SET status = 'DISABLED' WHERE client_id = :'client_id';` (no tool exists) | No tokens issued; issued bank and mobile tokens stop resolving; mobile and recovery requests refused; webhooks not delivered | Yes (`ACTIVE`) |
| Reset an admin account | `node dist/cli/createAdminUser.js <username> <role> [--client=<clientId>]` | New password and TOTP secret; every existing session of the account ends at its next request | New secrets only |
| Disable an admin account | Database change: `UPDATE admin_users SET status = 'DISABLED' WHERE username = :'username';` (no tool exists) | Sessions end at the next request; login refused (`account_disabled`) | Yes |
| End all tokens and sessions | Empty Redis (`FLUSHALL` on the Auth Core Redis) | All bank tokens, mobile tokens and admin sessions end; see [disaster recovery](disaster-recovery.md#redis) for side effects | No |
| Rotate the evidence key | [Key rotation](runbooks/key-rotation.md#evidence-sealing-key) | New records sealed with the new key | No |

`registerClient` sets the webhook URL and push mode to the values given; pass the current ones (`SELECT webhook_url, push_mode FROM bank_clients WHERE client_id = ...`). `createAdminUser` sets the role and bank scope given; without `--client` the account becomes a platform operator.

## Playbooks

### Bank client credentials compromised

Indicators: `oauth_token_issued` from unexpected `ip_address` or with an unexpected `details.certificateSha256`; `bank_certificate_mismatch`; bank API activity with `actor = bank:<clientId>` the bank does not recognise.

1. Rotate the client's secrets with `registerClient`, registering only fingerprints the bank confirms. This revokes all its tokens.
2. If the client certificate is also suspected, the bank revokes it at its CA and the gateway; register the replacement fingerprint with `setClientCertificates`.
3. If misuse continues, disable the client until the bank has new credentials in place.
4. Review what the client did in the period:

   ```sql
   SELECT event_type, count(*), min("timestamp"), max("timestamp")
   FROM audit_logs
   WHERE client_id = :'client_id' AND "timestamp" BETWEEN :'from' AND :'to'
   GROUP BY event_type ORDER BY 2 DESC;
   ```

   Pay attention to `mobile_session_issued` (BOOTSTRAP tokens), `credential_replacement_authorized`, `recovery_started`, `authorization_created` and `bank_commit_requested`. A holder of bank credentials can enrol a device for an identity without an enrolled device, replace a device with a replacement token, and open recovery sessions; the customer signature is still required for every authorization.
5. Revoke credentials enrolled through tokens the bank did not issue, and suspend affected identities ([lost, stolen or replaced device](runbooks/lost-or-stolen-device.md)).

### Unauthorized device replacement

Indicators: a customer reports the replacement notice; `credential.replaced` or `credential.replacement_requested` webhook, or `credential_replaced` event, without a matching bank case; `credential.replacement_cancelled` (the customer refused a replacement).

1. Suspend the identity.
2. Compare `credential_replacement_authorized` (`actor`, `details.method`, `details.reference`, `ip_address`) with the bank's case records.
3. Revoke the new credential (`details.newCredentialId` of `credential_replaced`).
4. Review authorizations confirmed by the new credential; their evidence names the credential and its sealed enrolment.
5. Re-enrol the customer's own device after re-identification; reactivate with four-eyes approval.
6. If the replacement token came from the bank's systems, continue with the bank client playbook.

### Admin account compromised or brute-forced

Indicators: `admin_login_failed` bursts, `admin_login` from unusual addresses, unexpected `admin_identity_viewed`, `admin_audit_log_viewed` or approval events.

1. Disable the account, or reset it with `createAdminUser` (the holder receives the new secrets over a separate channel). Both end its sessions.
2. Reject pending approvals it requested: `GET /admin/api/approvals`, then `POST /admin/api/approvals/{id}/reject` from another account.
3. Review the account's actions:

   ```sql
   SELECT "timestamp", event_type, nexus_id, ip_address, details
   FROM audit_logs
   WHERE actor LIKE 'admin:' || :'username' || '%' OR actor LIKE '%(requested by admin:' || :'username' || ')'
   ORDER BY "timestamp";
   ```

4. Suspensions it made are reversible (reactivation with four-eyes approval). Revocations it requested needed a second admin; review that admin as well.

### Evidence or database tampering

Indicators: `integrity_violation`; verifier `INVALID`, in particular `records missing at the end of the chain` or `differs from the head the bank received`; trigger or role changes in the database audit log.

1. Suspend the affected identities.
2. Collect the chain heads the bank stored for the affected identities and verify their chains with `--expect-head` and the evidence public keys from the key ceremony record.
3. Check that Auth Core runs as `nexus_app` and that all protective triggers are enabled ([evidence verification failure](runbooks/evidence-verification-failure.md#database-protections)).
4. Review `pgaudit` or the provider's audit log for trigger changes, `session_replication_role`, and writes to `evidence_records`, `credentials`, `nexus_identities`, `bank_clients` and `admin_users` outside Auth Core sessions.
5. Compare with the bank's WORM or SIEM copy of the evidence.
6. Once the scope is known: revoke credentials whose keys were substituted; customers enrol again after re-identification. If records were removed or altered, the database may need a restore and re-verification ([disaster recovery](disaster-recovery.md#database-restore)).

The sealed evidence makes changes detectable. It does not prevent a superuser from changing data, and a change made by someone who also controls the evidence key is detectable only against copies held outside Auth Core (bank heads, WORM exports).

### HSM evidence key compromised

Someone who can sign with the evidence key can seal records of their choice. Together with write access to the database, that includes `CREDENTIAL_ENROLLED` records for keys they control, which the runtime integrity check and the offline verifier would accept. Comparison with chain heads held by the banks and with WORM exports remains independent of the key.

1. The HSM team contains the HSM partition under the vendor's and the bank's procedures (external to Auth Core).
2. Generate a new evidence key and rotate to it ([key rotation](runbooks/key-rotation.md#evidence-sealing-key)). Record the time.
3. Decide, with the bank, what to do with the compromised key:

   | Option | Consequence |
   |---|---|
   | Do not list it in `EVIDENCE_RETIRED_PUBLIC_KEYS_PEM` | Every credential and recovery key sealed with it is refused at runtime (`integrity_violation`); every customer enrols again through device replacement and sets up recovery again |
   | List it, after the chains of all identities have been verified against bank-held heads and WORM copies made before the compromise | Customers keep their devices; the decision rests on that verification |

4. For disputes, evidence sealed with the compromised key is supported by the bank's head records and WORM copies dated before the compromise, not by the seal alone.

### Master key compromised

| Key | Exposure | Response |
|---|---|---|
| `WEBHOOK_SECRET_ENCRYPTION_KEY` | With database read access: every bank's webhook signing secret | New key and re-registration of every client with a webhook ([key rotation](runbooks/key-rotation.md#webhook_secret_encryption_key)) |
| `DEVICE_SECRET_ENCRYPTION_KEY` | With database read access: offline confirmation keys and push keys | New key; offline confirmation and push need re-enrolment and push registration per device ([key rotation](runbooks/key-rotation.md#device_secret_encryption_key)) |
| `ADMIN_SECRET_ENCRYPTION_KEY` | With database read access: admin TOTP secrets | New key and re-provisioning of every admin ([key rotation](runbooks/key-rotation.md#admin_secret_encryption_key)) |

### Database contents disclosed

What a copy of the database exposes: personal data (`bank_customer_ref`, beneficiary values, IP addresses, user agents), scrypt hashes of client secrets and admin passwords, AES-GCM ciphertexts that need the master keys, public keys, and evidence. Recovery data (public key and wrapped key) does not allow a recovery without the phrase; protocol 1 verifiers are no longer stored (migration 018). Rotate the master keys if they may have been exposed with the copy.

### Redis contents disclosed

Redis holds live bank tokens, mobile tokens and admin sessions, stored under the SHA-256 of the token, so the keys do not reveal the tokens; a copy of the values still shows which clients and identities had live sessions. Ending all of them: empty Redis. Bank backends request new tokens, admins log in again, apps request new tokens from the bank.

## Closing an incident

- Verify the chains of the affected identities against bank-held heads once more and keep the verifier output.
- Confirm no unexplained `integrity_violation`, `bank_certificate_mismatch` or admin events since containment.
- Record secrets rotated, credentials revoked, identities suspended or reactivated (with approval IDs), and the evidence key decision.
- Review whether the [threat model](../security/threat-model.md) needs a new entry.
