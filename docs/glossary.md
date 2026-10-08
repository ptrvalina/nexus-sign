# Glossary

| Term | Definition |
|---|---|
| Adaptive verification | Additional factors (AUDIO, VIDEO) that a bank can require before Auth Core accepts the device signature for an authorization. See [adaptive verification](architecture/adaptive-verification.md). |
| Attestation binding | The bytes that App Attest or Play Integrity attests at enrolment and recovery: the challenge, then the signing, authentication and offline public keys, separated by NUL bytes. One attestation covers all keys of a device, and it cannot be moved to another session or key. |
| Audit log | The `audit_logs` table. Every security-relevant state change writes an event in the same transaction as the change. |
| Auth Core | The NEXUS-SIGN server component, run by the bank. It holds identities, credentials and authorizations, verifies signatures and attestation, and seals evidence. |
| Authentication key | The device key that signs each request to Auth Core after enrolment. It needs an unlocked device but no biometric. |
| Authorization | A request by the bank backend for the customer to approve one transaction (`authorization_requests`). It moves from `PENDING_USER` to `VERIFIED`, `EXPIRED`, `REJECTED` or `CANCELLED`. |
| Authorization object | The 15-field JSON object of protocol v1 that describes one transaction and the credential that must sign it. See [protocol v1](protocol/authorization-protocol-v1.md). |
| Bank backend | The bank's server-side systems that call the Auth Core bank API with an OAuth access token through the bank's mTLS gateway. |
| Bank client | A bank backend registered with `node dist/cli/registerClient.js`, identified by `client_id`. All identities and authorizations belong to one bank client. |
| Bank transaction state | What the bank reports about executing a `VERIFIED` authorization: `PENDING`, `COMMIT_REQUESTED`, then `COMMITTED`, `FAILED` or `CANCELLED`. |
| BOOTSTRAP token | A single-use mobile token, valid for 300 seconds, that the bank backend issues for one NEXUS ID so the app can enrol a device (`POST /v1/mobile/bootstrap`). |
| Chain head | The position of the newest record in a NEXUS ID's evidence chain: `evidenceId`, `chainSequence` and `evidenceHash`. Auth Core returns it to the bank (identity `evidenceHead`, authorization and verification result `evidence`, chain export `head`); the bank stores it and passes it to `scripts/verify-evidence.mjs --expect-head`, so records removed from the end of the chain are detected. |
| Canonical payload | The exact bytes of the authorization object in canonical encoding: keys sorted recursively, `JSON.stringify` escaping, UTF-8. The device signs these bytes; `canonicalPayloadHash` is their SHA-256 in hex. |
| Client certificate fingerprint | The SHA-256 of a bank client's DER client certificate, forwarded by the mTLS gateway in `MTLS_CERT_SHA256_HEADER`. With `REQUIRE_MTLS_HEADER`, tokens are issued and accepted only when it is registered for the client (`bank_clients.mtls_cert_sha256`, set with `setClientCertificates` or `registerClient --mtls-cert-sha256`). See [ADR 0015](adr/0015-client-certificate-binding.md). |
| Device credential | The registered set of device public keys for one NEXUS ID, identified by a credential ID. It is `ACTIVE` until revoked, replaced by device replacement or replaced by recovery; then `REVOKED`. |
| Device-signed request | A request from an enrolled device authenticated by the `X-NEXUS-Credential`, `X-NEXUS-Timestamp`, `X-NEXUS-Nonce` and `X-NEXUS-Signature` headers instead of a token. Each nonce is accepted once. |
| Escalation | Raising the required verification factor of an authorization, by the bank backend or, if the policy allows it, by the customer. The required factor never decreases. |
| Evidence public key | The public half of the HSM key that seals evidence records, returned as `evidencePublicKeyPem`; `evidencePublicKeys` lists the current and retired keys by key ID (`sealKeyId`). Auditors obtain them out of band. |
| Evidence record | A sealed record in a NEXUS ID's chain (schema version 3): `AUTHORIZATION` (a `VERIFIED` authorization with the signed bytes, the device signature and the verification factors), `CREDENTIAL_ENROLLED` (a sealed enrolment) or `RECOVERY_CONFIGURED` (a registered recovery key). Each carries its chain position and link. See [evidence format](protocol/evidence-format.md). |
| Four-eyes approval | Revoking or reactivating a NEXUS ID in the admin console creates an approval request (`admin_approvals`) that is executed only when a second admin, with access to the same bank, approves it within `ADMIN_APPROVAL_TTL_HOURS`. Suspension needs one admin. See [ADR 0014](adr/0014-admin-scope-mfa-four-eyes.md). |
| Gateway mTLS | The bank's API gateway authenticates bank systems with client certificates and marks verified requests with a header that Auth Core accepts only from `TRUSTED_PROXY_IPS`. Device-facing endpoints are exempt. |
| Hash chain | The link between the evidence records of one NEXUS ID: each record carries the `evidenceHash` of the previous record, so a removed or reordered record is detectable. |
| Idempotency-Key | Request header of `POST /v1/authorizations`. A retry with the same key and the same request returns the original authorization; the same key with a different request is refused. |
| NEXUS ID | A stable nine-digit identifier for one bank customer within one bank client. It survives device replacement and recovery. |
| Offline challenge | The QR content (`NXS1.` followed by the base64url canonical payload) that a bank screen shows for offline confirmation. |
| Offline code | An 8-digit code that the phone derives, after a biometric check, from the canonical payload and a key shared with Auth Core. Auth Core can verify it; a third party cannot. |
| Offline key | The device key, agreed with Auth Core by ECDH at enrolment, from which offline codes are computed. It is usable only through the biometric prompt that shows the transaction. |
| Push key | The 32-byte key a device and Auth Core agree by ECDH when the app registers for secure push. Push messages for that device are sealed with it, and the device's delivery receipts are computed with it. |
| Push mode | Per bank client: `BANK`, the bank's own push system delivers authorization requests (package Sign); or `NEXUS`, Auth Core delivers them and the bank's messages through secure push (package Full Pack). |
| Push receipt | The HMAC under the push key with which a device confirms it decrypted a push message (`POST /v1/push-receipts/{id}`). The bank then receives `push.delivered`. |
| Recovery key | A P-256 key pair generated on the device at recovery setup (protocol 2). Auth Core stores the public key and the private key wrapped under a key derived from the recovery phrase, and seals the public key in a `RECOVERY_CONFIGURED` record. During recovery the device unwraps it with the phrase and signs the recovery proof. See [recovery protocol 2](protocol/recovery-protocol-v2.md). |
| Recovery phrase | Twelve BIP-39 words generated on the device. The phrase never leaves the device; it unwraps the recovery key during recovery. |
| Recovery session | A short-lived session (600 seconds, five attempts) that the bank backend opens after it has re-identified the customer, and that the new device uses to complete recovery. |
| Recovery verifier | Historical: the stored protocol 1 secret (SDK 1.4 and earlier), removed with protocol 1 in 2.0.0-rc.2 (migration 018). |
| Sandbox | The self-contained environment in `sandbox/` for workshops and integration rehearsals. It implements protocol v1 and simulates the bank, providers and HSM. |
| Seal | The HSM's ECDSA P-256 signature over the 32-byte `evidenceHash` of an evidence record (`hsmSignature`). |
| Sealed enrolment | The `CREDENTIAL_ENROLLED` evidence record written in the transaction that registers a credential, holding its public keys, platform, security level and attestation material. Auth Core compares a credential's stored keys with it before using them ([runtime integrity check](protocol/evidence-format.md#runtime-integrity-check)). |
| Secure push | Delivery of push messages to the bank's app through APNs and FCM, sealed for one device so that neither the providers nor Auth Core's database can read them. See [secure push](protocol/secure-push.md). |
| SESSION token | Historical: a bearer token for devices enrolled by SDKs before 1.2, removed in 2.0.0-rc.2. |
| Signing key | The device key that signs the canonical payload. It requires a biometric check for every use. |
| Step-up | Another name for escalation to a stronger verification factor. |
| Verification plan | The per-authorization record of required and current verification factors (`authorization_verification_plans`). A signature is accepted only when the plan has reached its required factor. |
| Verification session | An AUDIO or VIDEO check opened for one authorization, bound to a one-time nonce and valid for five minutes. The provider's result is reported through the bank's gateway. |
| Webhook | A signed HTTP notification from Auth Core to the bank, for example about a bank transaction state change, a device replacement or a recovery, delivered from an outbox with retries. |
| WYSIWYS | "What you see is what you sign": the SDK displays the transaction only from the signed bytes and refuses to sign when any displayed field differs from them. |
