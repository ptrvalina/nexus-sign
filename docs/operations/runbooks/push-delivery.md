# Push delivery

Bank clients in push mode `NEXUS` receive authorization requests and the bank's messages through secure push ([specification](../../protocol/secure-push.md)). Messages are written to `push_messages` sealed for one device and delivered to APNs or FCM by a worker that runs in every Auth Core process when `PUSH_DELIVERY_ENABLED=true`.

## Delivery behavior

| Item | Value |
|---|---|
| Poll interval | 1 s per process; a cycle starts only after the previous one has finished, then reports push timeouts |
| Batch | Up to 50 rows with `status = 'QUEUED'` and `next_attempt_at <= now()`, claimed with `FOR UPDATE SKIP LOCKED` and a 30 s lease |
| Request timeout | 10 s per provider request |
| Success | Provider accepted: `status = 'SENT'`, `sent_at`, `provider_message_id`. The device's receipt then sets `DELIVERED` and `delivered_at` |
| Retry delays | 5 s, 30 s, 2 min, 10 min, 30 min on 429, 5xx, timeouts and network errors, never past `expires_at` |
| Final failure | `FAILED` with `last_error`: `NO_PUSH_REGISTRATION`, `NO_ACTIVE_REGISTRATION`, `PUSH_KEY_REPLACED`, `PUSH_KEY_UNAVAILABLE`, `PUSH_DELIVERY_DISABLED`, `DEVICE_TOKEN_INVALID`, `REJECTED`, `RETRIES_EXHAUSTED`, `PROVIDER_NOT_CONFIGURED`; or `EXPIRED` (also when the next retry would come after the expiry) |
| Invalid token | APNs 410, `BadDeviceToken`, `DeviceTokenNotForTopic`; FCM `UNREGISTERED`, `SENDER_ID_MISMATCH`, 404: the registration becomes `INVALID` until the app registers a new token |

Every final state sends the `push.failed` webhook. An authorization request that is `SENT` without a receipt after its plan's `pushTimeoutSeconds` sends `push.timeout`.

## Symptoms

- `nexus_push_delivery_outcomes_total{outcome=~"failed|expired"}` increases, or `outcome="retried"` rises.
- `outcome="sent"` grows but `outcome="delivered"` does not: phones do not open the messages.
- The bank receives many `push.failed` or `push.timeout` webhooks.
- `Push delivery batch failed` log entries.
- `POST /v1/push-messages` answers 409 for customers who should have push.

## Impact

Customers do not see notifications, and in push mode `NEXUS` authorization requests do not reach the phone. Authorizations stay valid: the customer can still open the app and approve, and the bank can offer the offline code or escalate. No message content is exposed by a delivery failure; providers only ever receive sealed envelopes.

## Diagnosis

Queue overview:

```sql
SELECT provider, status, count(*), min(created_at) AS oldest
FROM push_messages
WHERE created_at > now() - interval '1 day'
GROUP BY provider, status
ORDER BY provider, status;
```

Latest errors:

```sql
SELECT message_id, provider, category, retry_count, last_http_status, left(last_error, 200) AS last_error, created_at
FROM push_messages
WHERE status IN ('QUEUED', 'FAILED', 'EXPIRED')
ORDER BY created_at DESC
LIMIT 50;
```

Registrations:

```sql
SELECT provider, apns_environment, status, count(*), max(updated_at) AS last_change
FROM push_registrations
GROUP BY provider, apns_environment, status;
```

One customer:

```sql
SELECT c.credential_id, c.state, c.platform, r.provider, r.apns_environment, r.status, r.last_error, r.updated_at
FROM credentials c LEFT JOIN push_registrations r ON r.credential_id = c.credential_id
WHERE c.nexus_id = :'nexus_id'
ORDER BY c.created_at DESC;
```

Read the pattern:

| Pattern | Likely cause |
|---|---|
| APNs `403 InvalidProviderToken` or `ExpiredProviderToken` on every message | `APNS_TEAM_ID`, `APNS_KEY_ID` or `APNS_PRIVATE_KEY_PEM` wrong, or the key revoked in the Apple Developer account |
| APNs `400 DeviceTokenNotForTopic` on every message | `APNS_TOPIC` is not the app's bundle ID |
| APNs `BadDeviceToken` for many devices | Development builds registered with `PRODUCTION`, or the reverse; check the app's `environment` argument |
| FCM `401` on every message | `FCM_SERVICE_ACCOUNT_JSON` invalid, or the service account lost its permission |
| FCM `SENDER_ID_MISMATCH` | `FCM_PROJECT_ID` is not the project the app's `google-services.json` belongs to |
| `PROVIDER_NOT_CONFIGURED APNS` or `FCM` | Devices of that platform register, but the provider is not configured |
| `NO_PUSH_REGISTRATION` on authorization requests | The app does not call `registerPush`, or the customer declined notifications |
| `NO_ACTIVE_REGISTRATION` | The credential was revoked or replaced after the message was queued, the app unregistered, or the token was retired |
| `PUSH_KEY_REPLACED` | The app agreed a new push key while messages were queued; expected after re-enrolment or a lost registration answer |
| `PUSH_KEY_UNAVAILABLE` | `DEVICE_SECRET_ENCRYPTION_KEY` changed or is missing: no stored push key can be read and every device has to register again |
| `PUSH_DELIVERY_DISABLED` | A bank client is in push mode `NEXUS` but `PUSH_DELIVERY_ENABLED` is off |
| Many `429` answers on `/v1/push-receipts` | A source sends receipts that do not verify (100 per 5 minutes locks it for 15 minutes); check for a misbehaving app version or probing |
| Many `SENT`, few `DELIVERED` | The iOS notification service extension does not run (missing `mutable-content` handling, keychain group not shared) or cannot reach Auth Core; on Android the app does not call `confirmPushReceipt` |
| Many `429` retries | Provider throttling; spread bulk messages over time |

## Resolution

1. Fix the cause: provider credentials and identifiers, the app's push integration, or network egress from Auth Core to `api.push.apple.com`, `api.sandbox.push.apple.com`, `oauth2.googleapis.com` and `fcm.googleapis.com` on port 443.
2. `QUEUED` rows continue on their schedule. To send them now:

   ```sql
   UPDATE push_messages SET next_attempt_at = now() WHERE status = 'QUEUED';
   ```

3. `FAILED` and `EXPIRED` rows are final and are not re-queued: their content is sealed for one device and may be outdated. The bank sends a new message with `POST /v1/push-messages` where it still matters. An authorization request is replaced by a new authorization.
4. A registration marked `INVALID` becomes `ACTIVE` again when the app next calls `registerPush` with a valid token.

## Follow-up

- Confirm the queue drains and `delivered` follows `sent` again.
- Tell the bank which customers had `push.failed`, so it can reach them through another channel.
- Record the cause and the time window.
