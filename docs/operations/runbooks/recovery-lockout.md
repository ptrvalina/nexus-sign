# Recovery lockout

Recovery replaces the device credential of a NEXUS ID when the customer proves knowledge of the recovery phrase (`auth-core/src/services/recoveryService.ts`, recovery protocol 2). The phrase never leaves the device. At setup the device generates a P-256 recovery key, wraps its private half under a key derived from the phrase (PBKDF2-HMAC-SHA256, 210,000 iterations, then HKDF) and registers the public half and the wrapped key, signed with its biometric signing key. Auth Core stores only these two values and seals the public key in a `RECOVERY_CONFIGURED` evidence record. At recovery the device unwraps the key with the phrase and signs a proof over the session, its nonce, the identity and the new signing key. Protocol: [recovery protocol 2](../../protocol/recovery-protocol-v2.md).

## Limits

| Item | Value |
|---|---|
| Who opens a session | The bank backend only, `POST /v1/recovery/sessions` with `{"bankCustomerRef":"..."}`, after it has re-identified the customer |
| Session lifetime | 600 s; the access token (`rc_...`) expires with the session |
| Proof attempts per session | 5 |
| Failed proofs per identity | 10 within 24 hours, summed over the sessions created in that window. From the tenth, `POST /v1/recovery/sessions` is refused with 409 `RECOVERY_LOCKED` |
| Use | A session completes at most once |
| Protocol 1 identities | Sessions and completions always refused with 409 `RECOVERY_PROTOCOL_RETIRED`; protocol 1 was removed in 2.0.0-rc.2 |

With protocol 2 a wrong phrase is detected on the device: the wrapped key does not open, and no request is sent, so typing errors use no server attempt. A proof that reaches Auth Core and fails comes from a device that holds a different recovery key or none.

A failed proof returns 401 (`Invalid recovery proof`) and writes a `recovery_failed` audit event with the attempt number; the attempt and the failure count are committed even though the request fails. After the fifth attempt, and after expiry or use, the session answers 404 (`Recovery session not found or expired`). Attestation is checked before the proof; with `REQUIRE_VALID_ATTESTATION=true` a failed attestation returns 403 and does not use an attempt.

The per-identity lock is checked when a session is opened, so a session opened before the tenth failure keeps its remaining attempts. The lock is not stored; it ends by itself when enough failed sessions are older than 24 hours. Auth Core has no operation that lifts it earlier.

## Symptoms

- The SDK reports that recovery failed; the bank backend sees 401 or 404 on sessions it opened.
- `POST /v1/recovery/sessions` returns:
  - 409 `RECOVERY_LOCKED` (`Too many failed recovery attempts for this customer; try again later`), with a `recovery_locked` audit event;
  - 409 `RECOVERY_PROTOCOL_RETIRED` (`The recovery phrase uses retired protocol 1; the customer must set up a new recovery phrase`);
  - 409 `Recovery has not been configured for this NEXUS ID`;
  - 409 `RECOVERY_INTEGRITY` (`Recovery configuration failed its integrity check`), with an `integrity_violation` audit event: the stored recovery key, salt or iteration count differ from the identity's latest sealed `RECOVERY_CONFIGURED` record, or the stored configuration is not that latest record;
  - 404 when the identity is not `ACTIVE` or the `bankCustomerRef` is unknown.
- Recovery completion returns 409 `RECOVERY_INTEGRITY` for the same check on the recovery key, with an `integrity_violation` audit event.
- Recovery setup on the device fails: 409 `RECOVERY_SETUP_EXPIRED` (the salt was issued more than 600 s ago or differs), 400 `The recovery setup is not signed by the device signing key` with a `recovery_setup_rejected` audit event.

## Impact

The customer cannot move the NEXUS ID to a new device with the phrase. Existing credentials keep working; a failed recovery revokes nothing.

## Diagnosis

Sessions of the identity:

```sql
SELECT recovery_session_id, protocol, created_at, expires_at, used_at, attempt_count, failed_attempt_count
FROM recovery_sessions
WHERE nexus_id = :'nexus_id'
ORDER BY created_at DESC
LIMIT 20;
```

The per-identity count, and when each failed session leaves the 24-hour window:

```sql
SELECT COALESCE(SUM(failed_attempt_count), 0) AS failures_24h
FROM recovery_sessions
WHERE nexus_id = :'nexus_id' AND created_at > now() - interval '24 hours';

SELECT created_at + interval '24 hours' AS leaves_window, failed_attempt_count
FROM recovery_sessions
WHERE nexus_id = :'nexus_id' AND created_at > now() - interval '24 hours' AND failed_attempt_count > 0
ORDER BY created_at;
```

Recovery events:

```sql
SELECT "timestamp", event_type, actor, ip_address, details
FROM audit_logs
WHERE nexus_id = :'nexus_id'
  AND event_type IN ('recovery_configured', 'recovery_setup_rejected', 'recovery_started', 'recovery_failed',
                     'recovery_locked', 'recovery_completed', 'integrity_violation')
ORDER BY "timestamp" DESC
LIMIT 50;
```

Recovery configuration and identity state:

```sql
SELECT nexus_id, status, recovery_protocol, recovery_public_key_pem IS NOT NULL AS has_recovery_key,
       recovery_evidence_id, recovery_updated_at
FROM nexus_identities
WHERE nexus_id = :'nexus_id';
```

| Finding | Meaning |
|---|---|
| `attempt_count = 5`, `used_at` empty | The session was locked by failed proofs |
| `failures_24h` 10 or more | The identity is locked; it opens again as the sessions in `leaves_window` age out |
| `expires_at` passed with fewer than 5 attempts | The session expired before completion |
| `recovery_failed` events on protocol 2 sessions | Proofs that did not come from the registered recovery key; treat as possible fraud |
| `recovery_protocol = 1` | Set up with SDK 1.4 or earlier; refused in production until the customer sets up a new phrase |
| `recovery_protocol` empty | The device never configured a phrase; recovery is not possible |
| `status` not `ACTIVE` | Suspended or revoked identity; no recovery session can be opened |
| `integrity_violation` with reason `recovery key: ...` | The stored recovery key or wrapped key differs from the sealed record; see [evidence verification failure](evidence-verification-failure.md) |

## Resolution

The bank backend decides, under its own customer authentication policy:

1. Session expired or locked, identity not locked, customer re-identified: open a new recovery session and let the SDK retry. A new session has its own nonce and five attempts.
2. Identity locked (`RECOVERY_LOCKED`) with a plausible explanation: wait until the window has passed (diagnosis query), or enrol the new device with a replacement token after re-identifying the customer ([lost or stolen device](lost-or-stolen-device.md#resolution)).
3. Phrase lost, recovery not configured, or protocol 1: enrol the new device with a replacement token after re-identifying the customer. The customer then sets up a new phrase on the new device. While the old device is still enrolled, a protocol 1 customer sets up a new phrase on it instead.
4. Pattern suggests an attack (failed protocol 2 proofs, sessions the customer did not request): suspend the identity in the admin console (`POST /admin/api/identities/{nexusId}/suspend`, one operator), contact the customer through a separate channel and follow [incident response](../incident-response.md).
5. `RECOVERY_INTEGRITY`: do not open further sessions; treat as an integrity incident.

## Follow-up

- After a completed recovery, confirm the new credential: `recovery_completed`, `credential_revoked` (reason `RECOVERY`) and `credential_created` events, the `identity.recovered` webhook, one `ACTIVE` row in `credentials` with a higher `key_version` and an `enrolment_evidence_id`, and the earlier credentials `REVOKED`. Recovery also cancels the identity's `PENDING_USER` authorizations.
- A completed recovery does not change the recovery key: the same phrase stays valid until a device sets up a new one (`POST /v1/mobile/recovery/setup`, which sends `recovery.configured`).
- Count the identities still on protocol 1, whose customers need a new phrase: `SELECT count(*) FROM nexus_identities WHERE recovery_protocol = 1;`
