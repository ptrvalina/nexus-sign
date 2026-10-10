# 0010. Recovery protocol 2: a recovery key wrapped under the phrase

## Status

Accepted

## Date

2026-10-06

## Context

In recovery protocol 1 the device derived a 32-byte PBKDF2 verifier from the recovery phrase and Auth Core stored it. The recovery proof was an HMAC of the session nonce keyed with the verifier. The stored value was therefore enough to produce a valid proof: whoever could read the database, a backup or a replica, and obtain a recovery session from the bank, could recover the identity without the phrase. The verifier worked as a password stored in clear.

Setting up the phrase was authorized by the device's request authentication, which needs no biometric, and the server did not require that the salt was one it had issued.

## Decision

- At setup the device generates a random P-256 recovery key in memory and wraps its private scalar with AES-256-GCM under `wrapKey = HKDF-SHA256(PBKDF2-HMAC-SHA256(phrase, salt, 210 000, 32), salt "NEXUS-SIGN/RECOVERY-WRAP/v2", info nexusId, 32)`, with associated data binding the NEXUS ID and the SHA-256 of the recovery public key.
- Auth Core stores the public key and the 60-byte wrapped key, never a value derived from the phrase that could produce a proof, and seals the public key in a `RECOVERY_CONFIGURED` evidence record ([ADR 0009](0009-evidence-schema-3.md)).
- Setup is signed by the device's biometric signing key over the identity, credential, salt, public key hash and wrapped key hash, and the salt must be the single-use salt Auth Core issued to that credential.
- A recovery session returns the public key and the wrapped key. The device opens the wrapped key with the phrase, so a wrong phrase fails on the device, and signs a proof over the session ID, nonce, NEXUS ID and the hash of the new signing key.
- Before checking a proof Auth Core compares the stored recovery key with its sealed record. (Extended in the same release: the check also runs when the bank creates the session, requires the identity's latest `RECOVERY_CONFIGURED` record, and at session creation compares the salt and iteration count with the sealed ones.)
- Five attempts per session; ten failed proofs per identity in 24 hours lock new sessions (409 `RECOVERY_LOCKED`).
- Protocol 1 is refused (409 `RECOVERY_PROTOCOL_RETIRED`) unless `RECOVERY_V1_ACCEPTED=true`, which is a production blocker. Protocol 1 can no longer be set up.
- Shared vectors (`recovery-v2.json`) pin the derivation, wrapping and signing inputs for Auth Core, iOS and Android.

Superseded in part by [0016](0016-remove-compatibility-paths.md): since 2.0.0-rc.2 `RECOVERY_V1_ACCEPTED` no longer exists, protocol 1 is always refused and the stored verifiers are dropped.

## Consequences

- Reading the database is no longer enough to complete a recovery, and substituting a recovery key in the database is detected.
- The wrapped key, salt and iteration count still allow an offline search of the phrase by anyone who holds them, including the bank backend through a recovery session. For an SDK-generated phrase the search space is 2^128 with 210 000 PBKDF2 iterations per guess; the attempt limits do not apply to this search.
- Customers on protocol 1 cannot recover in production until they set up a new phrase with SDK 2.0. Banks have to prompt them.
- The recovery private key is in app memory during setup and recovery; it cannot live in secure hardware because it must be restorable on another device.
- Replacing the recovery key needs a biometric prompt.
- A successful recovery leaves the recovery key unchanged.
- Specification and threat analysis: [recovery protocol 2](../protocol/recovery-protocol-v2.md).
