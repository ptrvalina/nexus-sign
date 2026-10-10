# HSM and key management

## Design

- A single `HsmAdapter` interface with a mandatory `healthCheck()`, executed at startup as a sign-and-verify self-test.
- **Production is fail-closed:** Auth Core does not start with the software adapter.
- **PKCS#11 adapter** (`pkcs11HsmAdapter.ts`) uses no vendor-specific API. It is loaded only when `HSM_ADAPTER=pkcs11`, so development and CI do not need the native module.
- **Device signature verification:** the customer's EC public key is imported into the HSM as an ephemeral session object (`CKA_TOKEN` false), destroyed after the operation.
- **Evidence sealing:** evidence is signed with the key selected below and an explicit key version. Every schema 3 record also names the sealing key by `sealKeyId` (SHA-256 of its SubjectPublicKeyInfo).
- **Signature encoding:** PKCS#11 ECDSA output (`r || s`) is normalized to DER for evidence and interchange.
- **Token selection:** by token label (`PKCS11_TOKEN_LABEL`, the token's `CKA_LABEL`). Exactly one present token must carry the label; none or several stop the session from opening. The slot index (`PKCS11_SLOT_INDEX`) is used only when no token label is set, as a development fallback, because an index can point at another token after tokens are added or the HSM restarts. Production requires the token label.
- **Key selection:** the private and the public key object are found by `CKA_LABEL` (`PKCS11_EVIDENCE_KEY_LABEL`) and, when set, `CKA_ID` (`PKCS11_EVIDENCE_KEY_ID`, hex). Each search must match exactly one object; two matches are an error, never a choice.
- **Key attribute checks:** when each session is opened, the private key must be EC on curve P-256, with `CKA_SIGN` true, `CKA_SENSITIVE` true and `CKA_EXTRACTABLE` false, and the public key must be an uncompressed P-256 point. The startup self-test signs a probe and verifies it with the public key, so a public key that does not belong to the private key is found before traffic arrives.
- **Key change detection:** a process that opens a session and finds a different public key than it started with fails with `The HSM evidence key changed while the service was running; restart after a key rotation`.
- **Sessions and deadlines:** sign and verify run on a pool of logged-in sessions through the asynchronous PKCS#11 calls, each with a deadline; see [HSM unavailable](../operations/runbooks/hsm-unavailable.md#adapter-behaviour).
- **No secret material in the repository:** no HSM PINs, vendor credentials, private keys or production certificates.

## Configuration

| Variable | Meaning |
|---|---|
| `HSM_ADAPTER` | `software` (development) or `pkcs11` |
| `PKCS11_MODULE_PATH` | Vendor PKCS#11 library |
| `PKCS11_TOKEN_LABEL` | Token label (1 to 32 characters); required in production. When set, `PKCS11_SLOT_INDEX` is ignored |
| `PKCS11_SLOT_INDEX` | Index into the slots with a token present; development fallback without a token label |
| `PKCS11_PIN` | From the secrets manager |
| `PKCS11_EVIDENCE_KEY_LABEL` | `CKA_LABEL` of the evidence key pair |
| `PKCS11_EVIDENCE_KEY_ID` | `CKA_ID` of the evidence key pair (hex); required when several keys share the label |
| `PKCS11_EVIDENCE_KEY_VERSION` | Version recorded in every evidence record (`hsmKeyVersion`); not derived or checked by Auth Core |
| `HSM_SESSION_POOL_SIZE` | Logged-in sessions per process (default 4) |
| `HSM_OPERATION_TIMEOUT_MS` | Deadline per operation and for waiting for a session (default 5000) |
| `EVIDENCE_RETIRED_PUBLIC_KEYS_PEM` | Public keys of evidence keys retired by rotation |

Full reference: [configuration](../operations/configuration.md#hsm). SoftHSM2 can stand in for a real HSM in integration environments (`test/integration/hsm.test.mjs`); see the header of `pkcs11HsmAdapter.ts`.

## Evidence key rotation

Rotation is a controlled key-management procedure run by the bank; the steps are in [key rotation](../operations/runbooks/key-rotation.md#evidence-sealing-key):

1. Record the current public key with its key ID and version.
2. Generate the new key pair in the HSM with a new label, or the same label and a new `CKA_ID`, meeting the attribute checks above.
3. Configure the new label (and ID), a higher `PKCS11_EVIDENCE_KEY_VERSION`, and append the previous public key to `EVIDENCE_RETIRED_PUBLIC_KEYS_PEM`.
4. Replace all processes in one step and confirm the startup self-test.
5. Keep every public key for the evidence retention period, outside Auth Core.

Auth Core accepts the current HSM key and the retired keys when it checks sealed enrolment and recovery records at runtime. A retired key missing from `EVIDENCE_RETIRED_PUBLIC_KEYS_PEM` makes every credential sealed with it fail the integrity check.

The evidence export endpoints return the current public key (`evidencePublicKeyPem`) and the current and retired keys by key ID (`evidencePublicKeys`). `scripts/verify-evidence.mjs` checks each schema 3 record with the key its `sealKeyId` names. For an independent check, pass the keys from the key ceremony record with `--public-keys=<file.pem>` (one file with every current and retired key); without it the verifier uses the keys inside the export, prints a `WARNING`, reports `EVIDENCE_SELF_CONSISTENT ... hsm_seal=verified_with_export_keys` and exits with code 3.
