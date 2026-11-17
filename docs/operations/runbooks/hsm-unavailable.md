# HSM unavailable

Auth Core uses the HSM to verify transaction signatures and to seal evidence (`auth-core/src/crypto/pkcs11HsmAdapter.ts`). Background: [HSM and key management](../../security/hsm-key-management.md); settings: [configuration](../configuration.md#hsm).

## Adapter behaviour

| Aspect | Behaviour |
|---|---|
| Initialisation | `C_Initialize` with `CKF_OS_LOCKING_OK`, because operations run on worker threads. `CKR_CRYPTOKI_ALREADY_INITIALIZED` is accepted. |
| Token selection | By `PKCS11_TOKEN_LABEL`: exactly one present token must carry the label, otherwise the session cannot be opened. Without a label, `PKCS11_SLOT_INDEX` into the slots with a token present (development fallback). |
| Key selection | Private and public key by `PKCS11_EVIDENCE_KEY_LABEL` and, when set, `PKCS11_EVIDENCE_KEY_ID` (`CKA_ID`). Each must match exactly one object; two matches are an error, never a choice. |
| Key checks | When each session is opened: private key EC, curve P-256, `CKA_SIGN` true, `CKA_SENSITIVE` true, `CKA_EXTRACTABLE` false, and generated in the HSM: `CKA_LOCAL`, `CKA_NEVER_EXTRACTABLE` and `CKA_ALWAYS_SENSITIVE` true (an imported key is refused); public key an uncompressed P-256 point. The self-test signs a probe and verifies it with the public key. |
| Session pool | Up to `HSM_SESSION_POOL_SIZE` (default 4) logged-in sessions per process, opened at startup and by the readiness check, and reused; a request opens a session only after one was retired. When all are busy, a caller waits for a free one up to `HSM_OPERATION_TIMEOUT_MS`. |
| Deadline | Every sign and verify has a deadline of `HSM_OPERATION_TIMEOUT_MS` (default 5000 ms), started before its first PKCS#11 call; the signing and verification steps themselves run through the asynchronous calls (`C_SignAsync`, `C_VerifyAsync`). On timeout the caller receives `HSM sign timed out after <n> ms` (or `verify`, or `session acquisition`); the session is never reused and is closed once the native call returns, and a replacement session can be opened. A timeout is not retried. |
| HSM not answering | A timed-out call keeps running in the native module and holds a libuv worker thread until the HSM answers. Once as many timed-out calls as `HSM_SESSION_POOL_SIZE` are still running, every new operation fails at once with `HSM session acquisition (HSM not answering) timed out after <n> ms`, instead of queueing more work, until some of them return. |
| Worker threads | The asynchronous calls share the libuv thread pool with DNS, file and scrypt work. The Docker image sets `UV_THREADPOOL_SIZE=16`; keep it larger than `HSM_SESSION_POOL_SIZE`, so that HSM calls stuck at a slow HSM do not starve the rest of the process. |
| Failed operation | The session is discarded, because it may hold an active operation. |
| Session loss | `CKR_SESSION_HANDLE_INVALID`, `CKR_SESSION_CLOSED`, `CKR_USER_NOT_LOGGED_IN`, `CKR_DEVICE_REMOVED`, `CKR_DEVICE_ERROR`, `CKR_TOKEN_NOT_PRESENT`, `CKR_OBJECT_HANDLE_INVALID` or `CKR_KEY_HANDLE_INVALID`: the operation is retried once on a new session. |
| Module loss | `CKR_CRYPTOKI_NOT_INITIALIZED` or `CKR_DEVICE_REMOVED`: the adapter calls `C_Finalize` and `C_Initialize` again, drops the idle sessions, retires the sessions in use when their calls return, and retries the operation once. Re-initialisation does not reduce the pool: new sessions are opened up to `HSM_SESSION_POOL_SIZE` as before. |
| Key change | If a newly opened session finds a different evidence public key than the process started with, it fails with `The HSM evidence key changed while the service was running; restart after a key rotation`. |
| Worker thread | The PKCS#11 module runs in its own worker thread (`pkcs11Worker.ts`); the service talks to it by messages (`hsmWorkerHost.ts`). A call that stalls in any PKCS#11 function, synchronous ones included (`C_OpenSession`, `C_Login`, `C_FindObjects*`, `C_SignInit`, `C_VerifyInit`, `C_CreateObject`), blocks that thread only; HTTP, health endpoints and other workers keep running, and the call fails with `HSM <op> timed out after <n> ms`. |
| Queue | At most `HSM_QUEUE_LIMIT` calls wait for the worker; more fail at once with `HSM queue is full`. |
| Circuit breaker | After `HSM_BREAKER_THRESHOLD` consecutive timeouts, or when the worker crashes, every call fails at once with `HSM unavailable: <reason>` and `/readyz` reports the HSM down, so the load balancer drains the instance. The stuck worker is terminated. After `HSM_BREAKER_COOLDOWN_MS` the next call starts a fresh worker, which must pass the health check (sign and verify a probe) before calls resume. A native call that never returns keeps its thread until the process restarts: if the breaker keeps reopening, restart the instance after the HSM is back. |
| Outcomes while the HSM is down | Authorizations cannot be confirmed (fail closed). Declines, expiries and cancellations are still recorded (migration 025) and sealed when the HSM is back. |
| Fallback | None. Nothing falls back to software keys. |

Which requests need the HSM:

| Needs a working HSM | Works without the HSM once the process has started |
|---|---|
| Transaction confirmation (`POST .../signature`, `POST /v1/mobile/authorizations/{id}/signature`, `POST .../offline-confirmation`): signature verification and evidence sealing | Device-signed request authentication (verified in Node.js with the sealed enrolment keys) |
| Device enrolment (`POST /v1/mobile/bootstrap`) and recovery completion: the `CREDENTIAL_ENROLLED` record is sealed | Identity and authorization creation, mobile sessions, bank commit calls, webhooks, push |
| Recovery setup (`POST /v1/mobile/recovery/setup`): signature check and `RECOVERY_CONFIGURED` record | Evidence exports, if the public key was read before the outage (it is kept in memory) |
| `/readyz` (self-test, reused for 30 s after a pass) | `/healthz` |

## Symptoms

At startup:

- The process exits with `Fatal error during startup`. The `err` field names the cause, for example:
  - `PKCS11_MODULE_PATH, PKCS11_PIN and PKCS11_EVIDENCE_KEY_LABEL are required when HSM_ADAPTER=pkcs11`
  - `No PKCS#11 token labelled '<label>' is present`, `More than one PKCS#11 token is labelled '<label>'`
  - `No PKCS#11 slot with a present token was found at PKCS11_SLOT_INDEX`
  - `HSM evidence private key '<label>' was not found` (or `public key`)
  - `More than one HSM private key is labelled '<label>'; set PKCS11_EVIDENCE_KEY_ID to select one`
  - `The HSM evidence key is not an EC key`, `... is not on curve P-256`, `... is not allowed to sign (CKA_SIGN)`, `... must be sensitive (CKA_SENSITIVE)`, `... must not be extractable (CKA_EXTRACTABLE)`, `HSM evidence key is not an uncompressed P-256 point`
  - `HSM evidence key pair self-test failed: the signature does not verify with the published public key`
  - `HSM sign timed out after <n> ms`, or a PKCS#11 return code (`CKR_...`) from the module
- Pods restart in a loop; `Starting NEXUS-SIGN Auth Core` is never logged.

While running:

- `/readyz` returns 503 and the log shows `Readiness check failed`; the load balancer takes the pods out of routing.
- Confirmation endpoints, enrolment, recovery completion and recovery setup return `500 Internal server error`, with `Unhandled error` log entries carrying a `CKR_...` code or `HSM ... timed out`.
- `The HSM evidence key changed while the service was running` after the key behind the label was replaced.

## Impact

- No authorization can be confirmed. Consuming an authorization and sealing its evidence happen in one database transaction; when the HSM call fails, the transaction rolls back and the authorization stays `PENDING_USER`.
- An HSM error is not an invalid signature and is not recorded in `authorization_attempts`, so the customer's five attempts are not used up. Authorizations that reach `expires_at` during the outage expire.
- No device can be enrolled or recovered, and no recovery phrase can be set up.
- A slow HSM shows as timeouts after `HSM_OPERATION_TIMEOUT_MS`; requests waiting for a session fail after the same deadline instead of blocking the process. An HSM that stops answering shows as `HSM not answering` errors without delay once `HSM_SESSION_POOL_SIZE` calls are stuck.

## Diagnosis

1. Read the startup or `Unhandled error` log entries and note the `CKR_...` code, the timeout or the message.
2. Check the token and key from a host with the same module and network path, using the vendor's tools or OpenSC `pkcs11-tool`:

   ```sh
   pkcs11-tool --module "$PKCS11_MODULE_PATH" --list-token-slots
   pkcs11-tool --module "$PKCS11_MODULE_PATH" --token-label "$PKCS11_TOKEN_LABEL" --login --pin "$PKCS11_PIN" --list-objects --type privkey
   pkcs11-tool --module "$PKCS11_MODULE_PATH" --token-label "$PKCS11_TOKEN_LABEL" --login --pin "$PKCS11_PIN" --list-objects --type pubkey
   ```

   Exactly one token must carry `PKCS11_TOKEN_LABEL`. On it, exactly one private key and one public key must match `PKCS11_EVIDENCE_KEY_LABEL` (and `PKCS11_EVIDENCE_KEY_ID` when set). The private key must show the usage `sign` and the attributes sensitive and not extractable.
3. Timeouts without `CKR_` codes point at the network path or the HSM's load. Compare the number of Auth Core processes times `HSM_SESSION_POOL_SIZE` with the session limit of the HSM partition.
4. Measure how many authorizations are waiting:

   ```sql
   SELECT count(*) AS pending, min(expires_at) AS next_expiry
   FROM authorization_requests
   WHERE state = 'PENDING_USER' AND expires_at > now();
   ```

## Resolution

1. Restore the HSM, its network path or the token (bank HSM team). Fix a configuration error named at startup (label, key ID, attributes).
2. A process that is running recovers by itself from a lost session or a lost module initialisation: the next operation opens a new session or re-initialises the module and retries once. Pods return to routing when `/readyz` passes again.
3. Restart the pods (rolling restart) when:
   - the log shows `The HSM evidence key changed while the service was running`;
   - errors continue after the HSM is confirmed healthy;
   - the configuration was changed.
4. Confirm `Starting NEXUS-SIGN Auth Core` with `"hsmAdapter":"pkcs11"` in the log of every restarted pod, and `/readyz` 200.
5. Confirm one authorization end to end, or run `npm run smoke-test` against a test client.

Do not switch to `HSM_ADAPTER=software`. Production startup refuses it, and the software adapter seals with a key generated in memory per process, so its seals cannot be verified after a restart.

Do not raise `HSM_OPERATION_TIMEOUT_MS` to hide an unstable HSM; requests then hold their database transaction and their client connection for longer.

## Follow-up

- Check that every confirmed authorization has evidence (expected: no rows):

  ```sql
  SELECT a.authorization_id
  FROM authorization_requests a
  LEFT JOIN evidence_records e ON e.authorization_id = a.authorization_id
  WHERE a.state = 'VERIFIED' AND e.evidence_id IS NULL;
  ```

- Check that every non-revoked credential has an enrolment record (expected: 0):

  ```sql
  SELECT count(*) FROM credentials WHERE state <> 'REVOKED' AND enrolment_evidence_id IS NULL;
  ```

- List authorizations that expired during the outage and tell the bank's payment operations:

  ```sql
  SELECT authorization_id, transaction_reference, expires_at
  FROM authorization_requests
  WHERE state IN ('PENDING_USER', 'EXPIRED') AND expires_at BETWEEN :'outage_start' AND :'outage_end'
  ORDER BY expires_at;
  ```

  Auth Core sets `EXPIRED` only when a confirmation arrives after `expires_at`; there is no background expiry job. An authorization past its expiry can therefore still show `PENDING_USER`.
- If the evidence key was replaced during the repair, follow [key rotation](key-rotation.md): the previous public key must go into `EVIDENCE_RETIRED_PUBLIC_KEYS_PEM`, otherwise every credential sealed with it fails the integrity check.
- The behaviour above is tested against SoftHSM 2.7 (`test/integration/hsm.test.mjs`). It has not been tested against the bank's HSM model; run the [release checklist](../release.md) HSM items with the vendor module.
