# Key management (FI-005)

Status: implemented and tested on SoftHSM 2.7.0. **Not validated on a production HSM** (gate G6 stays open). Design decision: D-027.

## Key inventory

| Key | Where it lives | Protects | Who uses it | Plaintext exists |
|---|---|---|---|---|
| Evidence sealing key (EC P-256) | HSM, non-extractable private key (`PKCS11_EVIDENCE_KEY_LABEL`) | Integrity of every evidence record (seals) | Auth Core processes (sign); auditors (public key) | Never outside the HSM |
| Key-encryption key (KEK, AES-256) | HSM, sensitive, non-extractable secret key (`PKCS11_KEK_LABEL`) | The three master keys (AES-256-GCM wrapping) | Auth Core processes at startup (decrypt); operator tools (`masterKeys.js`, encrypt and decrypt) | Never outside the HSM |
| `WEBHOOK_SECRET_ENCRYPTION_KEY` (master key) | Configuration: wrapped (`…_WRAPPED`); process memory after startup | Webhook signing secrets of the banks (`bank_clients.webhook_secret_encrypted`) | Auth Core (webhook worker), `registerClient`, `rotateSecretKeys` | In memory of those processes |
| `DEVICE_SECRET_ENCRYPTION_KEY` (master key) | As above | Offline confirmation keys (`credentials.offline_secret_encrypted`) and push keys (`push_registrations.push_key_encrypted`) | Auth Core (enrolment, offline confirmation, push), `rotateSecretKeys` | As above |
| `ADMIN_SECRET_ENCRYPTION_KEY` (master key) | As above | Admin TOTP secrets (`admin_users.totp_secret_encrypted`) | Auth Core (admin login), `createAdminUser`, `rotateSecretKeys` | As above |
| Stored secrets (per row) | Database, AES-256-GCM under a master key; format `k1$<key id>$…`, associated data `<purpose>:<owner>` | The secret itself | As above | Transiently, at use |
| PKCS#11 PIN | Configuration (`PKCS11_PIN`), from the secrets manager | Access to the token | Auth Core, operator tools | In memory and in the configuration |

Key IDs are identifiers, not key material: a master key ID is the first 8 bytes of SHA-256 of the key (hex), written into each ciphertext; a wrapped key names its KEK by label. Neither lets anyone derive a key.

## Modes

| `MASTER_KEY_SOURCE` | Configuration holds | Allowed |
|---|---|---|
| `env` | `<NAME>` and `<NAME>_PREVIOUS` in base64 | Development and tests only (production blocker) |
| `hsm` | `<NAME>_WRAPPED`, `<NAME>_PREVIOUS_WRAPPED`, `PKCS11_KEK_LABEL`; plaintext names are refused | Required in production |

Wrapped value: `w1$<KEK label>$<iv base64>$<ciphertext‖tag base64>`, AES-256-GCM made by the HSM (`C_Encrypt`, `CKM_AES_GCM`, 96-bit IV, 128-bit tag), associated data `nexus-sign/master-key/v1|<NAME>`. The associated data binds the wrapped key to its purpose: a wrapped webhook key configured as the device key does not unwrap.

## What the design changes, and what it does not

| Attacker has | Before (env) | Now (hsm) |
|---|---|---|
| Database copy | No secrets | No secrets |
| Database copy + configuration | All stored secrets (webhook secrets, offline keys, push keys, TOTP) | Nothing, unless they can also reach the HSM with the PIN from the configuration (test `master-key-hsm.test.mjs` "a copy of the database and the configuration does not open stored secrets") |
| Database + configuration + network access to the HSM | All | All (the HSM unwraps for anyone with the PIN). Restrict which hosts reach the HSM, use an HSM partition or user for Auth Core only, and vendor features such as client certificates for HSM sessions |
| Control of a running Auth Core process | All (memory) | All (memory). Not addressed; would need every secret operation inside the HSM (see "Not chosen") |
| Backup of the HSM token | — | The KEK (and the evidence key), subject to the HSM's backup protection |

## Access control

- The service unwraps: the KEK must have `CKA_DECRYPT`. Startup refuses a KEK that is extractable, not sensitive, not AES-256, or may not decrypt (`does not allow decryption (CKA_DECRYPT)`).
- Wrapping new master keys needs `CKA_ENCRYPT` (`masterKeys.js generate`/`wrap`/`rewrap`). Where the HSM supports separate users or partitions, give the service a partition or role with decrypt only and run key generation under an operator role; this is HSM-specific and not validated here. `create-kek --decrypt-only` creates a KEK that can only unwrap.
- `masterKeys.js` prints wrapped values and key IDs only. Errors name the key and the PKCS#11 return code, never input or key material. Auth Core logs no request bodies.

## Lifecycle

### Initial set-up (or migration from `env`)

1. KEK: on a production HSM, generate it in a key ceremony with the attributes `CKK_AES`, 32 bytes, `CKA_TOKEN`, `CKA_PRIVATE`, `CKA_SENSITIVE`, not `CKA_EXTRACTABLE`, `CKA_ENCRYPT`, `CKA_DECRYPT`, not `CKA_WRAP`/`CKA_UNWRAP`. On SoftHSM: `node dist/cli/masterKeys.js create-kek`.
2. New deployment: `masterKeys.js generate <webhook|device|admin>` for each purpose. Migration: `masterKeys.js wrap <purpose> < key.b64` with the existing key, then destroy the plaintext copy (the stored secrets do not change).
3. Configure `MASTER_KEY_SOURCE=hsm`, the `*_WRAPPED` values and `PKCS11_KEK_LABEL`; remove the plaintext variables. Check with `masterKeys.js check` (prints key IDs; they must equal the IDs of the old plaintext keys after a migration).

### Master key rotation (scheduled)

1. `masterKeys.js generate <purpose>`; configure the new value as `<NAME>_WRAPPED` and the old one as `<NAME>_PREVIOUS_WRAPPED`; restart all processes.
2. `rotateSecretKeys.js <purpose>` re-encrypts stored secrets; it can be interrupted and run again (tested with restarts in between).
3. Remove `<NAME>_PREVIOUS_WRAPPED`; restart.

### KEK rotation

1. Create a second KEK (`create-kek` with a new label, or a ceremony).
2. `masterKeys.js rewrap <purpose> --to-label=<new> < old-wrapped-value` for each configured value, including `_PREVIOUS_WRAPPED` ones. Key IDs do not change and no stored data is touched.
3. Configure the new values and `PKCS11_KEK_LABEL=<new>`; restart; `check`.
4. Destroy the old KEK only after every process runs with the new values and the old configuration cannot be rolled back to.

### Rollback

- Master key rotation: before `rotateSecretKeys` ran, remove the new key and restore the old value as `_WRAPPED`. After it ran, keep both (new current, old previous) and re-run the tool in the other direction by swapping them. Never drop a key while a stored value still names it (`rotateSecretKeys --dry-run` shows what remains).
- KEK rotation: the old wrapped values stay valid while the old KEK exists.

### Revocation and compromise

- Suspected master key compromise: rotate it and replace the protected secrets (runbook "Master key compromise").
- Suspected KEK or PIN compromise: rotate the KEK (above), change the PIN, rotate all three master keys, and treat the stored secrets as exposed if a database copy may also have leaked.

### Backup and recovery

- The KEK exists only in the HSM. Losing it loses the master keys and with them every stored secret: offline confirmation keys cannot be recreated (devices re-enrol), webhook secrets and TOTP secrets must be re-issued. Back the KEK up with the HSM vendor's mechanism (cloning to a backup HSM or wrapped backup under the vendor's backup key) as part of the key ceremony.
- Keep the wrapped values with the configuration backup; they are useless without the KEK.
- SoftHSM: the token directory is the backup unit (test and development only).

### Failure behaviour (fail closed)

| Situation | Result | Tested |
|---|---|---|
| PKCS#11 module missing or HSM unreachable at startup | Startup refused | yes |
| Wrong PIN | Startup refused: `HSM login refused (CKR_PIN_INCORRECT)` | yes |
| KEK label unknown, or the value names another KEK | Startup refused | yes |
| Wrapped value configured for another purpose, or damaged | Startup refused: `could not unwrap it (CKR_…)` | yes |
| KEK may not decrypt | Startup refused | yes |
| Plaintext key configured with `hsm` | Configuration error | yes |
| HSM unavailable after startup | No effect on master keys (already in memory); evidence sealing fails as before | evidence adapter tests |
| Stored value under a key not configured | That operation fails with the key ID named; `rotateSecretKeys` refuses to start | yes |

## Not chosen

- **All secret operations inside the HSM** (master keys as non-extractable HSM objects, AES-GCM per secret in the HSM): removes master keys from process memory, at the cost of an HSM call for every webhook delivery, offline check, push and admin login, and a dependency of those paths on HSM availability. Possible later; the stored format (`k1`) would not change if the master keys were HSM objects with the same key IDs.
- **`C_UnwrapKey` into session objects**: keeps keys in the HSM only if every use is an HSM operation, which is the previous option.

## Validation status

| Item | Status |
|---|---|
| SoftHSM 2.7.0: AES-GCM wrap and unwrap, attribute checks, failure modes, rotations | PASS (`master-key-hsm.test.mjs` 10/10) |
| Vendor HSM: AES-GCM with associated data via `CK_GCM_PARAMS`, attribute policy, partition/role separation, backup | BLOCKED: no HSM available |
| Key ceremony record | Not done |
