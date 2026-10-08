# Key rotation

This runbook covers the evidence sealing key, the per-client secrets (client secret and webhook signing secret) and the three master keys `WEBHOOK_SECRET_ENCRYPTION_KEY`, `DEVICE_SECRET_ENCRYPTION_KEY` and `ADMIN_SECRET_ENCRYPTION_KEY`. It states which rotations the code supports and which it does not.

| Key | Rotation supported by the code | Re-encryption of existing data |
|---|---|---|
| Evidence sealing key (HSM) | Yes, by configuration and restart; the retired public key stays configured in `EVIDENCE_RETIRED_PUBLIC_KEYS_PEM` | Not applicable; existing records keep their seal |
| Client secret and webhook signing secret (per bank client) | Yes, with `registerClient`, always both together | Not applicable |
| Client certificate fingerprints (per bank client) | Yes, with `setClientCertificates`, without rotating the secrets (`registerClient --mtls-cert-sha256` also sets them, but rotates the secrets) | Not applicable |
| `WEBHOOK_SECRET_ENCRYPTION_KEY` | No; one key, no fallback key | Only by re-registering each client |
| `DEVICE_SECRET_ENCRYPTION_KEY` | No; one key, no fallback key | Not implemented |
| `ADMIN_SECRET_ENCRYPTION_KEY` | No; one key, no fallback key | Only by re-provisioning each admin account (new TOTP secret) |

Device credential keys are separate: `credentials.key_version` increases when a device recovers, and is unrelated to `hsm_key_version`.

## Symptoms

- A scheduled rotation under the bank's key management policy.
- A key or secret is suspected compromised, or an HSM key reaches the end of its approved lifetime. For a suspected compromise also follow [incident response](../incident-response.md).

## Impact

### Evidence sealing key change

Every schema 3 record names the key that sealed it in `sealKeyId` (SHA-256 of the key's SubjectPublicKeyInfo, column `seal_key_id`). Auth Core itself verifies sealed records at runtime: before a credential's keys are used it checks the credential's `CREDENTIAL_ENROLLED` record, and before a recovery it checks the identity's `RECOVERY_CONFIGURED` record (`src/services/credentialIntegrity.ts`). It accepts the current HSM key and the keys in `EVIDENCE_RETIRED_PUBLIC_KEYS_PEM`.

- If the retired key is missing from `EVIDENCE_RETIRED_PUBLIC_KEYS_PEM` after a rotation, every credential enrolled before the rotation fails the integrity check (`the record was sealed with an unknown evidence key`): device-signed requests receive 401, confirmations return `FAILED` with `credential_integrity`, recovery setup 403, recovery session creation and completion 409 `RECOVERY_INTEGRITY`, and each refusal writes an `integrity_violation` audit event.
- Records sealed before the rotation keep their seal and `hsm_key_version`. They cannot be re-sealed, because `evidence_records` is append-only.
- Evidence exports carry `evidencePublicKeyPem` (the current key) and `evidencePublicKeys` (current and retired keys, by key ID).
- Each process reads the HSM public key when it opens its first session. A process that finds a different key behind the label while running fails with `The HSM evidence key changed while the service was running; restart after a key rotation`.
- During a rolling deployment old and new processes seal with different keys. A process still on the old configuration does not know the new key, so a credential enrolled on a new process is refused there (and audited as `integrity_violation`) until the old process is replaced. Replace all processes in one step, or stop traffic for the change.

### Client secret and webhook signing secret change

- `registerClient` generates a new client secret and revokes the client's access tokens at once. With a webhook URL it also generates a new webhook secret.
- It sets the webhook URL and the push mode to the values given: omitting the URL removes the webhook, omitting `--push-mode` sets `BANK`. Registered certificate fingerprints are kept unless `--mtls-cert-sha256` is given.
- Every delivery attempt after the change, including retries of events queued earlier, is signed with the new webhook secret.

### WEBHOOK_SECRET_ENCRYPTION_KEY change

`bank_clients.webhook_secret_encrypted` is AES-256-GCM output with no key identifier: `v2$iv$authTag$ciphertext` with the associated data `webhook:<clientId>` since 2.0, or `iv$authTag$ciphertext` from 1.4 (still decrypted; re-encrypted in the new format when the client is registered again). After a key change, every existing value stops decrypting:

- Deliveries for clients with a webhook fail and count as failed attempts; see [webhook backlog](webhook-backlog.md). Queuing an event does not decrypt the secret, so the API calls that queue events are not affected.

### DEVICE_SECRET_ENCRYPTION_KEY change

`credentials.offline_secret_encrypted` holds each credential's offline confirmation key, AES-256-GCM with `device:<credentialId>` as associated data and no key identifier. The plaintext key comes from a key agreement at enrolment with a server key pair that is discarded afterwards, so Auth Core cannot derive it again. `push_registrations.push_key_encrypted` uses the same master key. After a key change:

- `POST /v1/authorizations/{authorizationId}/offline-confirmation` returns 500 for every credential enrolled before the change. The QR challenge is still served. The failure does not use up attempts.
- Secure push messages cannot be sealed for devices registered before the change; they register for push again.
- Device-signature confirmation is not affected.

### ADMIN_SECRET_ENCRYPTION_KEY change

`admin_users.totp_secret_encrypted` is AES-256-GCM with the associated data `admin:<username>`. After a key change, no existing TOTP secret decrypts and no admin with a TOTP secret can log in until the account is re-provisioned. Bank and device traffic is not affected.

## Diagnosis

Evidence keys in use:

```sql
SELECT seal_key_id, hsm_key_version, count(*), min(created_at), max(created_at)
FROM evidence_records
GROUP BY seal_key_id, hsm_key_version
ORDER BY min(created_at);
```

`seal_key_id` is empty for records sealed before schema 3.

Key ID of a public key file, to match it with `seal_key_id`:

```sh
openssl pkey -pubin -in evidence-key-v1.pem -outform DER | sha256sum
```

Integrity failures after a change:

```sql
SELECT "timestamp", nexus_id, details->>'reason' AS reason, details->>'credentialId' AS credential_id
FROM audit_logs
WHERE event_type = 'integrity_violation' AND "timestamp" > :'change_time'
ORDER BY "timestamp" DESC LIMIT 50;
```

Clients affected by a change of `WEBHOOK_SECRET_ENCRYPTION_KEY`:

```sql
SELECT client_id, webhook_url, push_mode, mtls_cert_sha256 FROM bank_clients WHERE webhook_secret_encrypted IS NOT NULL;
```

Credentials affected by a change of `DEVICE_SECRET_ENCRYPTION_KEY`:

```sql
SELECT count(*) FROM credentials WHERE state = 'ACTIVE' AND offline_secret_encrypted IS NOT NULL;
```

Admin accounts affected by a change of `ADMIN_SECRET_ENCRYPTION_KEY`:

```sql
SELECT username, role, client_id FROM admin_users WHERE status = 'ACTIVE' AND totp_secret_encrypted IS NOT NULL;
```

## Resolution

### Evidence sealing key

Follow the bank's key ceremony and [HSM and key management](../../security/hsm-key-management.md), with these steps:

1. Save the current public key before the change and record it with its key ID and version. The current key is the entry of `evidencePublicKeys` whose key ID does not belong to a retired key; `evidencePublicKeyPem` of any export is the current key:

   ```sh
   curl -sS -H "Authorization: Bearer $TOKEN" "$AUTH_CORE/v1/nexus-identities/$NEXUS_ID/evidence" \
     | jq -r .evidencePublicKeyPem > evidence-key-v1.pem
   ```

2. Generate the new key pair in the HSM with a new label, or the same label and a new `CKA_ID`. The private key must be EC P-256, sign-capable, sensitive and not extractable; the public key object carries the same label and ID.
3. Prepare the new configuration:
   - `PKCS11_EVIDENCE_KEY_LABEL` (and `PKCS11_EVIDENCE_KEY_ID`) of the new key;
   - a higher `PKCS11_EVIDENCE_KEY_VERSION`;
   - `EVIDENCE_RETIRED_PUBLIC_KEYS_PEM` with the previous key appended to any keys already listed (PEM blocks concatenated). Never remove a key from this list while records sealed with it exist.
4. Replace all processes in one step. Each runs the sign-and-verify self-test with the new key at startup.
5. Confirm with the diagnosis query that new records carry the new `seal_key_id`, and that no `integrity_violation` events appear.
6. Save the new public key the same way and record it with its key ID and version. Keep every public key for the evidence retention period, outside Auth Core.

### Client secret, webhook secret and certificate fingerprints of one client

Run with the production configuration (`DATABASE_URL`, `REDIS_URL`, `WEBHOOK_SECRET_ENCRYPTION_KEY`), giving the client's current webhook URL and push mode:

```sh
node dist/cli/registerClient.js <clientId> <webhookUrl> --push-mode=<BANK|NEXUS> [--mtls-cert-sha256=<hex>[,<hex>]]
```

(`npm run register-client -- ...` runs the same command.) The tool prints the new `client_secret` and `webhook_secret` once. The bank backend switches to both new secrets when the tool runs; a webhook receiver that accepts the old and the new secret for a short window does not reject deliveries made in between.

For a certificate rollover use `setClientCertificates`, which replaces only the fingerprints and leaves the secrets and access tokens alone:

```sh
node dist/cli/setClientCertificates.js <clientId> <old hex>,<new hex>   # before the bank switches
node dist/cli/setClientCertificates.js <clientId> <new hex>             # after the switch
```

(`npm run set-client-certificates -- ...` runs the same command.) Register the old and the new fingerprint together, let the bank switch certificates, then register the new fingerprint alone.

### WEBHOOK_SECRET_ENCRYPTION_KEY

Re-encryption under a new master key is not implemented. The only supported path is re-registering each client with a webhook, which also rotates its client secret:

1. Agree a change window with every affected bank backend.
2. Deploy the new `WEBHOOK_SECRET_ENCRYPTION_KEY`.
3. Immediately run `registerClient` for each client from the diagnosis query, with the new key in the environment and the client's webhook URL and push mode, and hand over the printed secrets.
4. Confirm deliveries resume with the [webhook backlog](webhook-backlog.md) queries.

### DEVICE_SECRET_ENCRYPTION_KEY

Re-encryption is not implemented. After a key change, every affected customer must enrol the device again ([device replacement](lost-or-stolen-device.md)) or complete recovery before offline confirmation works for that customer again; until then the bank uses device-signature confirmation. Change this key only when it is compromised.

Setting `OFFLINE_CONFIRMATION_ENABLED=false` does not delete the stored values. Turning the feature on again with the same key restores offline confirmation for those credentials.

### ADMIN_SECRET_ENCRYPTION_KEY

1. Deploy the new key.
2. Re-provision every account from the diagnosis query with the new key in the environment, keeping its role and scope:

   ```sh
   node dist/cli/createAdminUser.js <username> <role> [--client=<clientId>]
   ```

   Each run enrols a new TOTP secret, sets a new password and ends the account's sessions. Without `--client` the account becomes a platform operator.
3. Hand the printed secrets to each account holder over a secure channel.

## Follow-up

- After an evidence key rotation, verify a chain that spans the rotation with a key file containing every evidence public key (`--public-keys`); see [evidence verification failure](evidence-verification-failure.md).
- After a client secret or master key change, confirm with each bank backend that token requests and webhook signature checks succeed.
- Generate replacement master keys as described in [configuration](../configuration.md#master-keys).
