# Database or Redis outage

Auth Core keeps durable state in PostgreSQL and short-lived state in Redis. Both are needed to serve requests, and Auth Core fails closed when either is unavailable: a request it cannot check is refused, never accepted.

| Store | Content |
|---|---|
| PostgreSQL | Bank clients, identities, credentials, authorizations and attempts, verification plans, recovery sessions, evidence, audit log, webhook queue, admin users |
| Redis | Bank access tokens (`oauth_token:*`), mobile BOOTSTRAP tokens (`mobile_session:*`), device request nonces (`device_nonce:*`), admin sessions, login throttle counters and lockouts |

## Symptoms

- `/readyz` returns 503 and pods leave routing; `Readiness check failed` in the log. `/healthz` stays 200.
- Requests that reach a pod return `500 Internal server error` with `Unhandled error` entries naming connection errors or timeouts.
- PostgreSQL: `Webhook delivery batch failed` every 2 s.
- New or restarted pods exit with `Fatal error during startup`: startup runs `SELECT 1` and `PING` and stops if either fails.

## Impact

PostgreSQL unavailable:

- Every API request that reads or writes state fails with 500, including token issuance, which checks the client secret in the database.
- No authorization is confirmed and no evidence is sealed. Webhooks wait in the queue.
- Queries are bounded by `DATABASE_STATEMENT_TIMEOUT_MS` (default 5000 ms).

Redis unavailable (a command fails after two retries, `maxRetriesPerRequest: 2` in `src/db/redis.ts`):

| Function | Behavior |
|---|---|
| Bank API calls | Access token lookup fails: 500 |
| `POST /oauth/token` | Throttle check fails: 500 |
| Device-signed mobile requests | The signature is checked, then the nonce cannot be recorded: 500, request refused |
| Mobile bearer tokens | Token lookup fails: 500 |
| Admin console | Session lookup and login throttle fail: 500 |
| Webhook delivery | Unaffected (PostgreSQL only) |

Redis data loss (an empty Redis after restart or failover):

- All bank access tokens, mobile tokens and admin sessions are gone. Bank backends receive 401 and must request a new access token. An SDK holding a BOOTSTRAP token receives 401 and needs a new token from the bank backend (`POST /v1/mobile/sessions`). Admins log in again. Devices that sign their requests are not affected.
- Login throttle counters and lockouts are reset.
- Recorded device nonces are gone. A captured device-signed request could be accepted once more until its timestamp leaves the `DEVICE_REQUEST_MAX_SKEW_SECONDS` window (default 300 s). After that window, no request recorded before the loss can be replayed.

## Diagnosis

```sh
curl -sS -o /dev/null -w '%{http_code}\n' "$AUTH_CORE_POD/readyz"
psql "$DATABASE_URL" -c 'SELECT 1'
redis-cli -u "$REDIS_URL" --tls PING
```

Check from the pod network, with the same TLS settings Auth Core uses (`DATABASE_SSL`, `rediss://`). Then check the provider's status: failover in progress, connection limits, certificate expiry, disk.

PostgreSQL connection pressure:

```sql
SELECT state, count(*) FROM pg_stat_activity WHERE datname = current_database() GROUP BY state;
```

Each Auth Core process opens up to `DATABASE_POOL_MAX` connections (default 10).

## Resolution

1. Restore the store (bank database or platform team).
2. Pods return to routing when `/readyz` passes; no restart is needed. Pods that failed at startup start normally once the store is reachable.
3. After Redis data loss, tell the bank backend teams that access tokens were invalidated.

## Follow-up

- Webhooks queued during the outage drain by themselves; check with [webhook backlog](webhook-backlog.md).
- Authorizations whose `expires_at` fell in the outage could not be confirmed:

  ```sql
  SELECT authorization_id, transaction_reference, expires_at
  FROM authorization_requests
  WHERE state IN ('PENDING_USER', 'EXPIRED') AND expires_at BETWEEN :'outage_start' AND :'outage_end';
  ```

- After Redis data loss inside the nonce window, review device-signed requests in the request log for the window around the loss (same `X-NEXUS-Credential` and `X-NEXUS-Nonce` twice).
