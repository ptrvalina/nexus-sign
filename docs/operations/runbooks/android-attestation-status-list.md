# Android attestation status list

Android enrolment and recovery are admitted only with a Keystore key attestation chain that ends at a Google root (`src/services/androidKeyAttestation.ts`). Google publishes the serial numbers of attestation certificates it has revoked or suspended in the attestation status list at `https://android.googleapis.com/attestation/status`. Auth Core does not download the list itself: operations download it to a file and keep it current, and Auth Core reads the file named by `ANDROID_ATTESTATION_STATUS_FILE`. Background: [Android key attestation](../../security/attestation.md#android-key-attestation).

Downloading the list needs outbound HTTPS access to `android.googleapis.com` from the host or job that fetches it. Auth Core itself does not need that access.

## How Auth Core uses the file

| Aspect | Behaviour |
|---|---|
| When it is read | Only while verifying an Android key attestation: `POST /v1/mobile/bootstrap` and recovery completion for an Android device. Existing credentials are not re-checked. |
| Caching | The parsed list is kept in memory for 60 seconds per process, then the file is read again. A refreshed file takes effect within about a minute without a restart. |
| Format | JSON with an `entries` object keyed by certificate serial number in hex, as Google publishes it. Serials are compared in lower case without leading zeros. |
| Effect of an entry | A chain that contains any certificate whose serial is listed is refused (`certificate <serial> of the attestation chain is <status>`), whatever the status value (`REVOKED`, `SUSPENDED`). An entry without a status counts as `REVOKED`. |
| Freshness | Auth Core does not check the age of the file or the list. A stale file is used as it is, without a warning: certificates revoked after the last download are accepted. |
| Variable unset | No revocation check. Allowed outside production; in production it is a startup blocker when Android attestation is configured. |
| File missing, unreadable or not valid JSON | The key attestation fails with the reason `key attestation: the attestation status list is unavailable (<error>)`; nothing is accepted as attested without the check. With `REQUIRE_VALID_ATTESTATION=true` the enrolment or recovery is refused with 403, like any other attestation failure. Startup does not read the file, so a missing file is noticed on the first Android enrolment. |

With `REQUIRE_VALID_ATTESTATION=true`, a refused chain makes the enrolment or recovery answer 403 `Device attestation verification failed`; the log entry `Device attestation refused` carries the reason.

## Download and refresh

Write to a temporary file in the same directory, check it, and rename it over the configured path, so Auth Core never reads a partly written file:

```sh
set -euo pipefail
target="$ANDROID_ATTESTATION_STATUS_FILE"
tmp="$(dirname "$target")/.status.$$"
curl -fsS --max-time 60 https://android.googleapis.com/attestation/status -o "$tmp"
jq -e '.entries | type == "object"' "$tmp" > /dev/null
mv -f "$tmp" "$target"
```

- Run the job on a schedule set by the bank, and once before the first Android enrolment. Record the chosen interval: `<refresh interval, set by the bank>`.
- The file must be readable by the user Auth Core runs as (`nexus` in the image) in every pod: a shared volume, a configuration object that the platform replaces atomically, or a sidecar.
- Keep the previous file when a download or the check fails; a failed refresh must alert, not empty the file.
- Monitor the age of the file (its modification time) and alert when it exceeds `<maximum age, set by the bank>`.

## Symptoms

- Android enrolments or recoveries fail with 403, and the `Device attestation refused` log entry carries `key attestation: the attestation status list is unavailable (...)` with `ENOENT`, `EACCES` or a JSON parse error: the file is missing, unreadable or malformed.
- Android enrolments fail with 403, and the `Device attestation refused` log entry carries the reason `key attestation: certificate <serial> of the attestation chain is REVOKED` (or `SUSPENDED`): the device's attestation key is listed by Google.
- Startup fails with `ANDROID_ATTESTATION_STATUS_FILE (Google attestation status list) is required in production`.

## Resolution

1. Missing or malformed file: run the download job, check the path in `ANDROID_ATTESTATION_STATUS_FILE` and the file permissions in a pod. No restart is needed.
2. A device refused because its attestation certificate is listed: this is the intended outcome. The device cannot enrol; the customer uses another device.
3. Several devices of one model refused after a refresh: compare the serials in the log with the list. If Google has revoked an intermediate used by a device family, the refusals stand; inform the bank's app support.

## Follow-up

- After a long period without refresh, list the Android credentials enrolled during that period. They passed with the old list; Auth Core does not re-check them:

  ```sql
  SELECT credential_id, nexus_id, created_at FROM credentials
  WHERE platform = 'ANDROID' AND state = 'ACTIVE' AND created_at BETWEEN :'stale_from' AND :'stale_to';
  ```

  The attestation chains are sealed in each credential's `CREDENTIAL_ENROLLED` record (`material.keyAttestation`), so the bank can re-check their serials against the current list and decide whether to ask those customers to enrol again.
