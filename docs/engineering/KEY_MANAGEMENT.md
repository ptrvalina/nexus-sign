# Key management

Status: implemented and tested on SoftHSM 2.7.0. **Not validated on a production HSM** (production HSM validation is still required). Design decision: D-027.

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
| SoftHSM 2.7.0: AES-GCM wrap and unwrap, attribute checks (incl. `CKA_LOCAL`/`CKA_NEVER_EXTRACTABLE` since phase 8), failure modes, rotations | Local test on SoftHSM only: `master-key-hsm.test.mjs` 11/11 passed (2026-10-18). Not a release-gate PASS: SoftHSM is not the production HSM |
| Vendor HSM: AES-GCM with associated data via `CK_GCM_PARAMS`, attribute policy, partition/role separation, backup | BLOCKED: no HSM available |
| Key ceremony record | Not done |

## Review of the implementation

Code review of `src/crypto/masterKeyVault.ts`, `src/crypto/secretBox.ts`, `src/cli/masterKeys.ts`, `src/cli/rotateSecretKeys.ts` against the questions of the phase 8 instruction. Own review, not an independent audit.

| Question | Finding |
|---|---|
| Algorithm and parameters | AES-256-GCM in the HSM (`CKM_AES_GCM`, `CK_PARAMS_AES_GCM`), 96-bit IV, 128-bit tag; a 32-byte key plus 16-byte tag is the only accepted ciphertext length |
| IV uniqueness | Random per wrap: HSM generator XOR Node's generator, so neither alone decides. Wraps are rare (key generation, rotation, KEK change), so a 96-bit random IV is far from the collision bound. The stored secrets under the master keys use Node's 96-bit random IVs (secretBox); same reasoning, volume is one secret per credential, webhook client or admin |
| Associated data | `nexus-sign/master-key/v1|<NAME>` for each master key; a wrapped key configured under another name fails to unwrap (test). Stored secrets: `device:<credentialId>` etc. (secretBox) |
| Key purpose and attributes | KEK: AES, 32 bytes, `CKA_SENSITIVE`, not `CKA_EXTRACTABLE`, and since D-031 `CKA_LOCAL` and `CKA_NEVER_EXTRACTABLE`; `CKA_DECRYPT` required for the service, `CKA_ENCRYPT` only for wrapping tools; `create-kek` sets `CKA_WRAP`/`CKA_UNWRAP` false |
| Encrypt/decrypt rights | A decrypt-only KEK (`create-kek --decrypt-only`) for production processes; an encrypt-capable one only where keys are wrapped (test: encrypt-only KEK refused by the service) |
| HSM unavailable | Startup fails closed with the PKCS#11 code only (`C_Initialize`, token missing, login refused, no KEK, wrong type) (tests) |
| Rotation and interruption | `rotateSecretKeys.js` decrypts everything before writing (an unknown key stops it before any write: tested), then re-encrypts in batches of 200, each in a transaction; by design an interruption leaves each row under the old or the new key, both in the ring (`_PREVIOUS`), and a second run re-encrypts the rest. Tested: rotation with server restarts before and after; **not tested: killing the tool in the middle of a run** |
| Key of another purpose | Refused by the associated data (test) |
| Logs | Errors carry only `CKR_*` codes and names; the CLI prints wrapped values, never plaintext (test greps the logs for key material) |
| Production mode | `MASTER_KEY_SOURCE=hsm` required; plaintext keys next to `hsm` refused (tests) |
| Plaintext keys in memory | **Yes.** After startup the three master keys and every configured `_PREVIOUS` key are Buffers in the Auth Core process for its lifetime (and in the operator tools while they run). Per-use copies of the offline key `K` are wiped after the code comparison; other decrypted secrets (webhook secrets, admin TOTP seeds) are short-lived values not explicitly wiped. JavaScript gives no guarantee that the runtime has not copied a Buffer |
| Could the application avoid plaintext master keys? | Possible without changing the stored format (D-032): master keys as non-extractable HSM objects and `C_Decrypt` per secret. Not implemented: needs vendor validation and does not stop an attacker who controls the process from using the HSM |

## Checks and the in-HSM option (2026-10-18)

Checks of the current code, with the test that shows each (local, SoftHSM 2.7.0; not a vendor HSM):

| Requirement | Evidence | Status |
|---|---|---|
| Production requires the HSM for master keys | `productionBlockers`: `MASTER_KEY_SOURCE must be hsm in production`; unit test `production-posture.test.mjs` | Verified (unit) |
| No fallback to plaintext keys | With `hsm`, `masterKeyMaterial` returns only what was unwrapped at startup and throws if nothing was loaded; plaintext values next to `hsm` stop the start (`master-key-hsm` test) | Verified locally |
| Imported KEK refused | `master-key-hsm`: KEK created with `C_CreateObject` from a known value is refused (`CKA_LOCAL`, `CKA_NEVER_EXTRACTABLE`) | Verified on SoftHSM |
| KEK not extractable | Startup refuses `CKA_EXTRACTABLE` true or `CKA_SENSITIVE` false; `create-kek` sets both | Verified on SoftHSM |
| HSM failure stops startup | HSM unavailable, wrong PIN, unknown KEK, wrong purpose, decrypt-forbidden KEK (tests) | Verified on SoftHSM |
| KEK change and key rotation survive restarts | `master-key-hsm` (KEK change, rotation across restarts), `key-rotation` | Verified locally; interruption of the rotation tool mid-run not tested |
| Backup and restore | Described above (vendor cloning or wrapped backup of the KEK; wrapped values with the configuration backup) | Documented only; not exercised |
| No key material in logs | Log scans in `master-key-hsm` | Verified locally |
| Plaintext master keys in process memory | Unchanged | **Open** |

### Can the application stop holding the master keys?

`test/integration/hsm-in-place-decryption.test.mjs` (SoftHSM) records:

1. **Format: yes.** A secret in the stored `k1` format (AES-256-GCM, 96-bit IV, 128-bit tag, associated data `<purpose>:<owner>`) decrypts with `C_Decrypt` and `CKM_AES_GCM` under an HSM key object that holds the same master key; wrong associated data is refused by the HSM. No change of the stored format is needed.
2. **Migration of the existing keys: not on SoftHSM.** Turning a wrapped master key into a non-extractable HSM object without the plaintext passing through the process needs `C_UnwrapKey`; SoftHSM 2.7.0 answers `CKR_MECHANISM_INVALID` for `CKM_AES_GCM`, and the RFC 5649 alternative (`CKM_AES_KEY_WRAP_PAD` through `C_Encrypt`) is also refused. The workable path is a **new** master key generated in the HSM (`C_GenerateKey`, never extractable) and a rotation of every stored secret to it (`rotateSecretKeys.js` would then encrypt through the HSM). Vendor HSMs differ: some do not allow a caller-supplied GCM IV for `C_Encrypt` (FIPS mode), which the stored format needs.
3. **Cost: about 20 µs per secret on SoftHSM**, in-process. A network HSM adds its round trip (typically milliseconds) to every offline code check, webhook signing, push key use and admin TOTP check.

What it would and would not change: a memory dump of Auth Core would no longer contain the master keys, but whoever controls the process can still ask the HSM to decrypt any secret, so the offline-confirmation boundary does not move. Not implemented in phase 9: it needs a vendor HSM to validate (mechanisms, IV policy, latency, availability), and a design for HSM outages on the hot paths. Status of "keys in process memory": **not closed**.

## Rotation status (2026-10-18)

| Item | Evidence | Status |
|---|---|---|
| Rotation tool killed mid-run | `key-rotation-interrupted.test.mjs`: 260 stored offline keys, second batch held on a row lock, tool killed with SIGKILL; the first batch (200) stays under the new key, the interrupted batch is rolled back entirely (60 under the old key), every secret decrypts unchanged, Auth Core with both keys in the ring confirms offline, a second run re-encrypts the remaining 60, then the old key is not needed | Verified locally (software HSM; master keys from the environment) |
| KEK change interrupted | `masterKeys.js rewrap` writes new `*_WRAPPED` values to standard output and changes no stored data; an interruption leaves the old configuration valid | By design; nothing to roll back |
| Restart at each step of a rotation | before the tool, after it, and in the middle (above); the ring accepts both keys throughout | Verified locally |
| Rotation to a master key generated inside the HSM | needs the tool to encrypt through the HSM (`C_Encrypt` with a caller-supplied GCM IV): not implemented; the SoftHSM capability check shows the stored format decrypts in the HSM, but not every vendor HSM accepts a caller IV | Not implemented; vendor HSM BLOCKED |
| Plaintext master keys in process memory | unchanged | Open |

## Keys the bank holds (2026-10-19)

| Key or record | Holder | Rotation | Notes |
|---|---|---|---|
| Bank trust key (ECDSA P-256) | The bank, in its own HSM. Never Auth Core. | New key added to the bank's list of trust public keys. Statements signed with the old key stay valid while its public key stays in the list. Remove it from the list only after re-signing the registry. | Signs credential approvals and revocations ([bank credential trust v1](../protocol/bank-credential-trust-v1.md)). `bankKeyId` = SHA-256 of its SubjectPublicKeyInfo. |
| Pinned evidence public keys | The bank, from the key ceremony record and each evidence key rotation (current and retired keys), out of band | Every evidence key rotation adds one | `bank-execution-check.mjs --public-keys`. The keys inside an export are never used for the decision. |
| Chain heads | The bank, from every `evidence.appended` | — | `--expect-head`, `--heads`. Truncation after the last kept head cannot be detected. |

`scripts/bank-trust-statement.mjs` signs with a private key file and exists for development and tests only. A production bank backend signs inside its HSM.

## Operating the bank's trust registry (2026-10-19)

| Item | Requirement |
|---|---|
| Bank trust key | Generated and used in the bank's HSM. The backend asks the HSM to sign each statement. No export, no copy in Auth Core's infrastructure. Dual control for rotation. |
| Trust registry database | Separate from Auth Core's, with its own credentials and no network path from Auth Core. Statements are append-only (trigger). Revocations are final; a credential is bound to one customer (trigger). Backed up together with the execution journal and restored as one. |
| Pinned evidence keys, bank trust public keys | Configuration under change control, from the key ceremony record; never read from an Auth Core response. |
| Kept heads | Written from every `evidence.appended` (`keepHead`), at approval, and after each execution; forward only. Lost heads reduce detection to what the chain shows. |
| Execution journal | Each payment executes once. Monitor and alert on `HELD`, `OUTCOME_UNKNOWN`, `REVIEW` and `REFUSED`; a `REFUSED` with an approval or seal problem is a security incident. `REVIEW` is settled by a person against the payment system. |
| Access | Only the backend's approval service writes statements; only the execution boundary holds the gateway's client certificate, and only the gateway's role may submit. Operators read; changes go through the bank's own four-eyes procedure. |
