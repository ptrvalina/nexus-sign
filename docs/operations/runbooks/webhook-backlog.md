# Webhook backlog

Auth Core notifies the bank backend of bank transaction events through webhooks (`auth-core/src/services/webhookService.ts`). Events are written to `webhook_deliveries` in the same transaction as the state change and delivered by a worker that runs in every Auth Core process.

## Delivery behavior

| Item | Value |
|---|---|
| Event types | `authorization.bank_transaction.commit_requested`, `.committed`, `.failed`, `.cancelled` |
| Poll interval | 2 s per process; a cycle starts only after the previous one has finished |
| Batch | Up to 20 rows with `status = 'PENDING'` and `next_attempt_at <= now()`, oldest `next_attempt_at` first, claimed with `FOR UPDATE SKIP LOCKED` |
| Claim lease | `next_attempt_at` is moved 30 s ahead while a row is in flight; if the process dies, the row is picked up again after the lease |
| Request timeout | 10 s, no redirects, connection only to the address checked by the URL policy |
| Success | HTTP 2xx: `status = 'DELIVERED'`, `delivered_at`, `last_http_status` |
| Retry delays | 1 s, 5 s, 30 s, 5 min, 30 min after attempts 1 to 5 (`retry_count` 1 to 5) |
| Final failure | After the sixth failed attempt: `status = 'FAILED'`, `retry_count = 6` |
| No destination | If the client is not `ACTIVE` or has no webhook at delivery time: `FAILED` at once, `last_error = 'No webhook destination configured at delivery time'` |

Every failed attempt, including a non-2xx response, a timeout (`Webhook delivery timed out`), a network error or a URL policy error (`Webhook host is not allow-listed`, `Webhook URL must use HTTPS`, `Webhook target resolves to a private or reserved address`), is retried on the schedule above. The signature headers are computed at each attempt with the client's current webhook secret. Receivers deduplicate on `eventId` (`X-NEXUS-SIGN-Event-Id`), which does not change between attempts.

## Symptoms

- `nexus_webhook_delivery_outcomes_total{outcome="failed"}` increases, or `outcome="retried"` rises.
- The bank backend reports missing or late notifications.
- `Webhook delivery batch failed` log entries.
- `POST /v1/authorizations/{authorizationId}/bank-commit-request` or `bank-commit-result` returns 500 (see the decryption case below).

## Impact

Webhooks are notifications. The authorization and bank transaction state in Auth Core is correct and can be read with `GET /v1/authorizations/{authorizationId}/bank-transaction`. A bank backend that depends on webhooks for reconciliation sees events late or not at all until the backlog clears.

## Diagnosis

Queue overview:

```sql
SELECT status, count(*), min(created_at) AS oldest
FROM webhook_deliveries
GROUP BY status;
```

Pending rows by client:

```sql
SELECT client_id, count(*), max(retry_count) AS max_retries, min(next_attempt_at) AS next_due
FROM webhook_deliveries
WHERE status = 'PENDING'
GROUP BY client_id;
```

Latest errors:

```sql
SELECT id, event_id, client_id, event_type, retry_count, next_attempt_at, last_http_status, left(last_error, 200) AS last_error
FROM webhook_deliveries
WHERE status IN ('PENDING', 'FAILED')
ORDER BY created_at DESC
LIMIT 50;
```

The admin console shows the same data: `GET /admin/api/webhook-deliveries?status=PENDING&limit=100` (statuses `PENDING`, `DELIVERED`, `FAILED`; limit at most 500).

Read the pattern:

| Pattern | Likely cause |
|---|---|
| `last_http_status` 4xx or 5xx | Receiver rejects or fails; with 401 or 403, check the receiver's signature verification and clock tolerance |
| `Webhook delivery timed out` or connection errors | Receiver down or slow, network or firewall path |
| URL policy messages | `WEBHOOK_ALLOWED_HOSTS`, `WEBHOOK_REQUIRE_HTTPS`, or DNS resolving to a private or reserved address |
| `last_error = 'Webhook secret could not be decrypted'` | Wrong or changed `WEBHOOK_SECRET_ENCRYPTION_KEY` |
| Rows `PENDING` with `retry_count = 0`, `last_error` empty, `created_at` older than a few minutes, plus `Webhook delivery batch failed` in the log | The worker cycle fails before any attempt, most often a database problem; see the log entry |
| No rows due but events missing | Events are queued only for clients with a webhook URL and secret: `SELECT client_id, webhook_url IS NOT NULL AS has_url, webhook_secret_encrypted IS NOT NULL AS has_secret, status FROM bank_clients;` |

When the webhook secret does not decrypt (wrong or changed `WEBHOOK_SECRET_ENCRYPTION_KEY`), each attempt is counted as failed and retried on the schedule above, so the rows reach `FAILED` after the sixth attempt. Queuing does not decrypt the secret, so the bank commit calls keep working.

## Resolution

1. Fix the cause: receiver availability, network path, allow-list, DNS, or the encryption key (see [key rotation](key-rotation.md)).
2. Pending rows continue on their schedule. To deliver them without waiting for the next retry:

   ```sql
   UPDATE webhook_deliveries
   SET next_attempt_at = now()
   WHERE status = 'PENDING' AND client_id = :'client_id';
   ```

3. `FAILED` rows are not retried by Auth Core and there is no API to re-queue them. To re-queue under the bank's change control:

   ```sql
   UPDATE webhook_deliveries
   SET status = 'PENDING', retry_count = 0, next_attempt_at = now(), last_error = NULL, last_http_status = NULL
   WHERE status = 'FAILED' AND client_id = :'client_id' AND created_at >= :'since';
   ```

   Re-queued rows keep their `event_id`, so a receiver that already processed an event discards the duplicate.

## Follow-up

- Confirm the queue drains: the first query shows no old `PENDING` rows.
- Ask the bank backend to reconcile the affected authorizations with `GET /v1/authorizations/{authorizationId}/bank-transaction`.
- Record the cause and the time window.
