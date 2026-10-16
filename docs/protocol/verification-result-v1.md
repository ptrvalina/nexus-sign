# Verification result v1

How an audio or video verification provider reports a result that Auth Core checks itself (FI-002). Implementation: `auth-core/src/services/verificationResult.ts`, `auth-core/src/crypto/jws.ts`. Tests: `auth-core/test/integration/verification-results.test.mjs`.

## Parties

| Party | Role | Trusted for |
|---|---|---|
| Verification provider | Holds the call (or the automated check) and signs the result | The result it signs, within its stated assurance |
| Bank verification gateway | Relays the token to Auth Core over mTLS with the bank's OAuth token | Transport only; it cannot change or invent a result |
| Auth Core operator | Registers provider public keys per bank (`cli/verificationSetup.js`) | Which keys may sign |
| Device | Opens the session and receives `sessionId` and `nonce` | Passing the nonce to the provider inside the call |

A bank that answers calls with its own staff can use operator verification in the admin console instead of a provider; see [adaptive verification](../architecture/adaptive-verification.md).

## Token

Compact JWS ([RFC 7515](https://www.rfc-editor.org/rfc/rfc7515)), ES256 only (ECDSA P-256 with SHA-256, signature as `r || s`, 64 bytes).

Header:

| Field | Value |
|---|---|
| `alg` | `ES256` (anything else, including `none`, is refused) |
| `typ` | `nexus-verification-result+jwt` |
| `kid` | The key ID registered with the provider key |

`jwk`, `jku`, `x5c`, `x5u` and `crit` are refused: the key is always taken from the registry.

Claims:

| Claim | Content | Checked against |
|---|---|---|
| `iss` | Provider ID, `[A-Za-z0-9._-]{1,64}` | Registry: `(bank, iss, kid)` must be an `ACTIVE` key registered for the session's channel |
| `aud` | `nexus-sign:<clientId>` | The bank that relays the token |
| `sub` | Verification session ID | The session in the URL |
| `authorization_id` | Authorization ID | The session's authorization |
| `canonical_payload_hash` | SHA-256 (hex) of the signed transaction bytes | The authorization; a result for other terms is refused |
| `credential_id` | Device credential ID | The credential the authorization is bound to |
| `channel` | `AUDIO` or `VIDEO` | The session's channel |
| `result` | `VERIFIED` or `FAILED` | — |
| `session_nonce_sha256` | SHA-256 (hex) of the session nonce the device received | The session; ties the result to the call the device joined |
| `iat`, `exp` | Seconds since the epoch | `iat` at most 60 s in the future, `exp` in the future, `exp - iat` at most 600 |
| `jti` | 16 to 128 characters `[A-Za-z0-9._:-]` | Not used before by the same key for the bank |
| `assurance` | Optional provider label, up to 64 characters | Recorded as given |

The request body is `{ "resultToken": "<JWS>" }`. Any other field is refused (400).

## Outcome

- **Accepted.** The session is closed with the result, `method = PROVIDER`, `issuer = <providerId>/<keyId>`, `jti`, and the SHA-256 of the token. The evidence of the authorization lists the factor with these fields.
- **Refused.** The response is 403 with the reason, an audit event `verification_result_rejected` is written, and the session stays open. A token for a closed session returns 409.

## What the token does and does not prove

- It proves that the holder of a registered provider key stated this result, for this session, these transaction terms, this device and this time.
- It does not prove how the provider reached the result, the identity of the person in the call, liveness, or resistance to synthetic media. These depend on the provider and are outside Auth Core.
- It never authorizes the transaction. The device signature over the same transaction bytes is still required after the plan is satisfied.
