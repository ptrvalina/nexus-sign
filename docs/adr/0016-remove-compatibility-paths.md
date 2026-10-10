# 0016. Remove compatibility paths and unused schema

## Status

Accepted

## Date

2026-10-07

## Context

Release 2.0.0-rc.1 still contained paths that existed only for development or for data and devices from 1.x:

- Bank-side credential provisioning and rotation (`POST /v1/nexus-identities/{nexusId}/credentials`, `POST /v1/credentials/{credentialId}/rotate`) registered device keys that no device attestation covered. They were refused with `REQUIRE_VALID_ATTESTATION`, but remained an enrolment path without attestation in every other configuration.
- Recovery protocol 1 kept the stored verifiers in `nexus_identities.recovery_verifier`. A verifier is the HMAC key of the protocol 1 proof, so it works as a password for anyone who can read it (NXS-003). `RECOVERY_V1_ACCEPTED` could turn protocol 1 back on.
- `SESSION` tokens gave devices enrolled by SDKs before 1.2 a bearer token for the mobile API, so a token that could be copied and replayed still existed for some enrolled devices.
- The schema permitted states and tables that Auth Core never wrote: authorization states `CREATED`, `DELIVERING`, `SIGNED`, `CONSUMED`, credential states `PENDING`, `SUSPENDED`, the column `credentials.suspended_at` and the tables `attestation_records` and `policy_decisions`.

Each of these widened the attack surface (unattested keys, password-equivalent verifiers, bearer tokens for enrolled devices) or the set of states a direct database write could produce. The product owner approved their removal before the final 2.0 release.

## Decision

In 2.0.0-rc.2:

- The two bank-side provisioning and rotation endpoints are removed (404). Devices enrol only through `POST /v1/mobile/bootstrap`, with attestation per policy; a device change goes through [device replacement](0012-explicit-device-replacement.md) or recovery. Sealed enrolment reasons are `ENROLMENT`, `REPLACEMENT`, `RECOVERY` and `BASELINE`; verifiers accept any reason string, so chains with `ROTATION` or `BANK_PROVISIONED` records from earlier versions still verify.
- Recovery protocol 1 is removed. `RECOVERY_V1_ACCEPTED` no longer exists; `POST /v1/recovery/sessions` and recovery completion answer 409 `RECOVERY_PROTOCOL_RETIRED` for every identity still on protocol 1. Migration 018 drops `nexus_identities.recovery_verifier`; `recovery_protocol` keeps the value 1 for those identities.
- `SESSION` tokens are removed. `POST /v1/mobile/sessions` issues only single-use `BOOTSTRAP` tokens (300 s) and answers 400 to `purpose: "SESSION"`; `MOBILE_SESSION_TTL_SECONDS` no longer exists. `POST /v1/mobile/bootstrap` and recovery completion require `authPublicKeyPem` and always answer `requestAuthentication: DEVICE_SIGNATURE`. `SESSION` tokens still in Redis are refused (401).
- Migration 018 drops the two unused tables, restricts authorization states to `PENDING_USER` → `VERIFIED` | `EXPIRED` | `CANCELLED` | `REJECTED` and credential states to `ACTIVE` → `REVOKED`, drops `credentials.suspended_at`, and permits the bank transaction transition `PENDING` → `COMMIT_REQUESTED` only for a `VERIFIED` authorization. Suspension remains a state of the NEXUS identity. The migration stops with an error naming the rows when existing data uses a removed state or the dropped tables hold rows.

## Consequences

- Breaking for bank backends: the two provisioning endpoints return 404; `purpose: "SESSION"` returns 400; customers on recovery protocol 1 cannot recover.
- Breaking for apps: devices enrolled by SDKs before 1.2 (no authentication key) can no longer call the mobile API. The bank re-enrols them through device replacement. In the SDKs, `NEXUSTokenPurpose` has only `BOOTSTRAP`, and device requests without an enrolled device fail with `notRegistered` (iOS) or `NEXUSSignError.NotRegistered` (Android).
- Customers on protocol 1 set up a new phrase on their enrolled device; a customer who has lost the device is enrolled again through device replacement after the bank's re-identification.
- Before applying 018, operators revoke credentials in `PENDING` or `SUSPENDED`, resolve authorizations in a removed state, and export and empty `attestation_records` and `policy_decisions` if they hold rows. The revoke endpoint of 2.0.0-rc.2 accepts only `ACTIVE` credentials.
- A database reader no longer finds any recovery secret, and no enrolled device holds a reusable token.
- Specifications: [state machines](../architecture/state-machines.md), [device authentication](../protocol/device-authentication-and-offline-confirmation.md), [recovery protocol 2](../protocol/recovery-protocol-v2.md), [migrations](../../auth-core/migrations/README.md).
