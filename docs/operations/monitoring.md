# Monitoring

Auth Core exposes Prometheus metrics, two health endpoints and structured JSON logs (pino). Thresholds in the suggested alerts are set by the bank unless a value is given by the code.

## Health endpoints

Both endpoints are unauthenticated and are served ahead of the gateway mTLS check (`auth-core/src/app.ts`).

| Endpoint | Checks | Response |
|---|---|---|
| `GET /healthz` | Nothing; the process answers HTTP | Always `200 {"status":"ok"}` |
| `GET /readyz` | `SELECT 1` on PostgreSQL, `PING` on Redis and the HSM sign-and-verify self-test (a passed self-test is reused for 30 s) | `200 {"status":"ready"}`, or `503 {"status":"not ready"}` with a `Readiness check failed` warning in the log |

Use `/healthz` for liveness and `/readyz` for readiness, so that a PostgreSQL, Redis or HSM outage takes pods out of routing without restarting them. The HSM self-test also runs at startup; a failing self-test there stops the process. See [HSM unavailable](runbooks/hsm-unavailable.md).

## Metrics

`GET /metrics` returns the Prometheus text format. With `REQUIRE_MTLS_HEADER=true` it is subject to the gateway check like any bank-facing route: the scraper must reach Auth Core from an address in `TRUSTED_PROXY_IPS` and send the `MTLS_VERIFIED_HEADER` header with the value `SUCCESS`, otherwise it receives 403. Auth Core does not distinguish the scraper from a bank backend: any caller that passes the gateway check can read `/metrics`. The metrics are aggregates per route, method and status code, per delivery outcome, and the default process metrics; they carry no bank client, NEXUS ID or credential labels. Restricting which caller may scrape `/metrics` is a deployment control at the gateway (for example a separate listener or a path rule for the monitoring system's certificate).

Metrics are per process. Aggregate across pods in the query.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `nexus_http_request_duration_seconds` | Histogram | `method`, `route`, `status_code` | Request duration. Buckets: 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5 s. |
| `nexus_http_requests_total` | Counter | `method`, `route`, `status_code` | Completed requests. |
| `nexus_webhook_delivery_outcomes_total` | Counter | `outcome` | Webhook delivery attempts by outcome: `delivered`, `retried` (a retry was scheduled), `failed` (the delivery reached `FAILED`). |
| `nexus_authorization_confirmations_total` | Counter | `method` | Authorizations confirmed (`VERIFIED`): `DEVICE_SIGNATURE`, `OFFLINE_CODE` (v1), `OFFLINE_SIGNED` (v2). Counted in the confirming transaction, so a transaction that rolls back afterwards is still counted. |
| `nexus_sealed_outcomes_total` | Counter | `subject`, `outcome` | Outcomes sealed into the evidence chain, once each: `subject` `AUTHORIZATION` with `outcome` `REJECTED`, `CANCELLED`, `EXPIRED`, `OFFLINE_UNSIGNED` and the others; `subject` `CREDENTIAL` for revocations. With the confirmations counter this gives the confirmation success rate. |
| `nexus_evidence_unsealed_outcomes` | Gauge | — | Outcomes recorded but not yet sealed (set by the expiry sweep). Grows while the HSM is unavailable. |
| `nexus_hsm_breaker_state` | Gauge | — | HSM circuit breaker: 0 closed, 1 half-open, 2 open (HSM calls fail closed). Only with `HSM_ADAPTER=pkcs11`. |
| `nexus_hsm_in_flight` | Gauge | — | PKCS#11 operations queued or running in the HSM worker. Only with `HSM_ADAPTER=pkcs11`. |
| `nexus_push_delivery_outcomes_total` | Counter | `provider`, `outcome` | Secure push outcomes. `provider`: `APNS`, `FCM`, or `none` when the message never reached a provider. `outcome`: `sent` (accepted by the provider), `retried`, `delivered` (receipt from the device), `failed`, `expired`. |

The `route` label is the Express route pattern, for example `/v1/authorizations/:authorizationId/signature` or `/oauth/token`, never the concrete URL. Requests that did not reach a route handler share `route="unmatched"`. These include unknown paths and requests rejected by authentication middleware before the handler: bank requests without a valid access token and mobile requests without a valid token or device signature (both 401). `POST /v1/mobile/sessions` and `POST /v1/recovery/sessions` check the bank token inside the route and keep their own `route` label.

The HTTP metrics do not cover `/healthz`, `/readyz`, `/metrics`, the admin console (`/admin`, `/admin/api/*`) or requests rejected by the gateway mTLS check, because those are handled before the metrics middleware.

The registry also carries the prom-client default process and Node.js metrics, without a prefix, for example `process_cpu_seconds_total`, `process_resident_memory_bytes`, `nodejs_eventloop_lag_seconds` and `nodejs_heap_size_used_bytes`.

Auth Core exports no metrics for queue depth, HSM latency, attestation outcomes or recovery attempts. These are visible in the database (`webhook_deliveries`, `push_messages`, `authorization_attempts`, `audit_logs`); the runbooks contain the queries.

## Logs

Logs are JSON lines on standard output. The level is `info` when `NODE_ENV=production` and `debug` otherwise.

### Correlation ID

Every request gets an ID. Auth Core reuses the caller's `X-Correlation-Id` header, or `X-Request-Id` if that is absent, and otherwise generates a UUID. The ID is returned in the `X-Correlation-Id` response header and logged as `req.id`. A bank backend that sends its own ID can find a request in both systems' logs.

The `correlationId` field in the body of `POST /v1/authorizations` is separate: it is stored in `authorization_requests.correlation_id` and sealed into the evidence record.

### Request log entries

pino-http writes one entry per completed request with `req` (`id`, `method`, `url`, `headers`, remote address and port), `res` (`statusCode`, `headers`) and `responseTime` in milliseconds.

The following are replaced with `[redacted]`:

| Path | Content |
|---|---|
| `req.body`, `res.body` | Request and response bodies |
| `req.headers.authorization` | Bank access tokens, Basic client credentials, mobile and recovery bearer tokens |
| `req.headers.cookie` | Admin session cookie |
| `req.headers["x-nexus-signature"]` | Device request signature |
| `res.headers["set-cookie"]` | Admin session cookie on login |

`X-NEXUS-Credential`, `X-NEXUS-Timestamp` and `X-NEXUS-Nonce` are logged in clear. They identify a device credential and a request; they are not secrets.

### Application messages

| Message | Level | Meaning |
|---|---|---|
| `Starting NEXUS-SIGN Auth Core` | info | HSM self-test passed; carries `hsmAdapter` and `env` |
| `Auth Core listening` | info | Server is accepting connections |
| `Fatal error during startup` | fatal | Configuration, posture, HSM, PostgreSQL or Redis check failed; the process exits with code 1 |
| `Readiness check failed` | warn | `/readyz` returned 503 |
| `Unhandled error` | error | A request ended in 500; carries `err`, `path`, `method` |
| `Webhook delivery batch failed` | error | A webhook worker cycle threw; see [webhook backlog](runbooks/webhook-backlog.md) |
| `Secure push delivery enabled` | info | The push worker started; carries the configured `providers` |
| `Push delivery batch failed` | error | A push worker cycle threw; see [push delivery](runbooks/push-delivery.md) |
| `Unhandled promise rejection` | error | A rejected promise outside the request pipeline |

## Suggested alerts

| Condition | Example expression or source | Runbook |
|---|---|---|
| Pods not ready | Readiness probe failures from the orchestrator | [Database or Redis outage](runbooks/database-or-redis-outage.md) |
| Authorization confirmation failing with 500 | `sum(rate(nexus_http_requests_total{route=~".*/signature\|.*/offline-confirmation",status_code="500"}[5m])) > 0` | [HSM unavailable](runbooks/hsm-unavailable.md) |
| Overall server error ratio | `sum(rate(nexus_http_requests_total{status_code=~"5.."}[5m])) / sum(rate(nexus_http_requests_total[5m]))` above a bank-set ratio | Depends on the log entries |
| Latency | `histogram_quantile(0.99, sum by (le, route) (rate(nexus_http_request_duration_seconds_bucket[5m])))` above a bank-set value | |
| Webhook deliveries reaching `FAILED` | `increase(nexus_webhook_delivery_outcomes_total{outcome="failed"}[15m]) > 0` | [Webhook backlog](runbooks/webhook-backlog.md) |
| Webhook retries | `rate(nexus_webhook_delivery_outcomes_total{outcome="retried"}[15m])` above a bank-set rate | [Webhook backlog](runbooks/webhook-backlog.md) |
| Webhook worker errors | Log message `Webhook delivery batch failed` | [Webhook backlog](runbooks/webhook-backlog.md) |
| Push messages failing | `sum by (provider) (increase(nexus_push_delivery_outcomes_total{outcome=~"failed\|expired"}[15m]))` above a bank-set count | [Push delivery](runbooks/push-delivery.md) |
| Push accepted but not received | Ratio of `outcome="delivered"` to `outcome="sent"` over 1 h below a bank-set value | [Push delivery](runbooks/push-delivery.md) |
| Push worker errors | Log message `Push delivery batch failed` | [Push delivery](runbooks/push-delivery.md) |
| Confirmation success rate falls | `sum(rate(nexus_authorization_confirmations_total[1h])) / (sum(rate(nexus_authorization_confirmations_total[1h])) + sum(rate(nexus_sealed_outcomes_total{subject="AUTHORIZATION"}[1h])))` below a bank-set ratio | Check declines (`outcome="REJECTED"`) against expiries (`EXPIRED`: push or device problems) |
| HSM breaker open | `max(nexus_hsm_breaker_state) == 2` for 1 m | [HSM unavailable](runbooks/hsm-unavailable.md) |
| Outcomes not sealed | `max(nexus_evidence_unsealed_outcomes) > 0` for 10 m | [HSM unavailable](runbooks/hsm-unavailable.md) |
| Startup failure | Log message `Fatal error during startup`, or restart loops | [HSM unavailable](runbooks/hsm-unavailable.md) |
| Token endpoint throttling | `rate(nexus_http_requests_total{route="/oauth/token",status_code="429"}[5m]) > 0` | |
| Authentication rejections | `rate(nexus_http_requests_total{route="unmatched",status_code="401"}[5m])` above a bank-set rate | |
| Invalid signatures and recovery failures | SQL on `authorization_attempts` and `audit_logs`, collected by the bank's SQL exporter or SIEM | [Recovery lockout](runbooks/recovery-lockout.md) |

A webhook whose secret does not decrypt counts as a failed attempt (`last_error = 'Webhook secret could not be decrypted'`) and reaches `FAILED` on the normal schedule.
