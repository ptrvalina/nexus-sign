# Runbooks

Each runbook has the same sections: symptoms, impact, diagnosis, resolution and follow-up. SQL matches `auth-core/src/db/schema.sql` and runs with `psql "$DATABASE_URL"` (role `nexus_app`, or `nexus_audit_reader` for read-only queries on evidence and audit records); values written as `:'name'` are psql variables, passed with `-v name=value`. HTTP examples use `$AUTH_CORE` for the Auth Core base URL behind the bank's gateway and `$TOKEN` for a bank access token. Bank calls go through the gateway with a client certificate registered for the client:

```sh
TOKEN=$(curl -sS --cert client.pem --key client.key -u "$CLIENT_ID:$CLIENT_SECRET" -d grant_type=client_credentials \
  "$AUTH_CORE/oauth/token" | jq -r .access_token)
```

Admin console API calls (`/admin/api/*`) need the `nexus_admin_session` cookie of an admin logged in with password and TOTP code; state changes need the `operator` role or higher, and revocation and reactivation of an identity need a second admin's approval. A bank-scoped admin sees only that bank's identities. CLI commands (`node dist/cli/...`) run from the release image or a build with the production configuration; `scripts/` runs from a checkout of the release tag.

| Runbook | Use when |
|---|---|
| [HSM unavailable](hsm-unavailable.md) | Startup fails at the HSM checks, `/readyz` fails on the HSM, or confirmations, enrolment and recovery return 500 |
| [Webhook backlog](webhook-backlog.md) | Webhook deliveries stay `PENDING`, retry or reach `FAILED` |
| [Push delivery](push-delivery.md) | Secure push messages stay `QUEUED`, fail, or are not received by phones |
| [Database or Redis outage](database-or-redis-outage.md) | `/readyz` returns 503, or most requests return 500 |
| [Lost, stolen or replaced device](lost-or-stolen-device.md) | A customer reports a lost, stolen or replaced phone, or a BOOTSTRAP request returns 409 `ACTIVE_CREDENTIAL_EXISTS` |
| [Recovery lockout](recovery-lockout.md) | A customer cannot complete recovery, or recovery sessions return 409 `RECOVERY_LOCKED` or `RECOVERY_PROTOCOL_RETIRED` |
| [Evidence verification failure](evidence-verification-failure.md) | `scripts/verify-evidence.mjs` reports `INVALID`, or `integrity_violation` audit events appear |
| [Key rotation](key-rotation.md) | Rotating the evidence sealing key, a bank client's secrets or certificates, or a master key |
| [Android attestation status list](android-attestation-status-list.md) | Setting up or refreshing `ANDROID_ATTESTATION_STATUS_FILE`, or Android enrolment fails on the status list |

Related: [incident response](../incident-response.md), [disaster recovery](../disaster-recovery.md), [upgrade to 2.0](../upgrade-2.0.md), [configuration](../configuration.md), [monitoring](../monitoring.md), [deployment](../deployment.md).
