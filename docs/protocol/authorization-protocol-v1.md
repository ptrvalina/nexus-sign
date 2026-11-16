# Transaction authorization protocol v1

The protocol defines the exact bytes a customer's device signs to authorize a single transaction. Auth Core, the iOS SDK, the Android SDK and the sandbox implement it independently. The shared vectors in `auth-core/test-vectors/signed-payload-v1.json` pin all four implementations to the same bytes.

## Authorization object

A JSON object with exactly these 15 fields. All values are strings, except `beneficiary`.

| Field | Format |
|---|---|
| `protocol_version` | `"1"` |
| `domain` | `"NEXUS-SIGN/TRANSACTION-AUTH"` |
| `authorization_id` | UUID |
| `nexus_id` | 9-digit NEXUS ID |
| `credential_id` | UUID of the device credential that must sign |
| `transaction_reference` | Bank transaction reference, unique per bank client |
| `operation_type` | e.g. `transfer` |
| `amount_minor` | Non-negative integer in minor units, decimal string without leading zeros, at most 30 digits |
| `currency` | ISO 4217 code, `^[A-Z]{3}$` |
| `beneficiary` | Object of string values; keys match `^[a-z][a-z0-9_]{0,63}$`; at most 16 fields; values of 1 to 140 UTF-16 code units (ISO 20022 Max140Text) with no leading or trailing space separator (Zs). Up to 2.0.0-rc.2: up to 512 |
| `policy_reference`, `policy_version` | Bank policy under which the authorization was issued |
| `issued_at`, `expires_at` | RFC 3339 UTC with milliseconds, e.g. `2026-09-26T10:00:00.000Z` |
| `nonce` | 32 random bytes, lowercase hex |

Floating-point numbers never appear in the object. Beneficiary keys are restricted because JavaScript enumerates integer-like keys (`"0"`, `"10"`) before all other keys, which would break the sorted-key rule below.

No string field may contain a character of Unicode general category Cc (control, including line breaks), Cf (format: bidi overrides and isolates, zero-width characters, soft hyphen) or Zl/Zp (line and paragraph separator). These characters change how text is laid out without being visible, so a payee name could push the real IBAN out of the confirmation prompt or reorder it. Auth Core refuses them when the authorization is created and the device refuses signed bytes that contain them.

## Canonical encoding

1. Sort object keys recursively in UTF-16 code-unit order (the order of `Array.prototype.sort`).
2. Serialize with `JSON.stringify` semantics: no whitespace. Strings escape only `"`, `\`, the control characters U+0000 to U+001F (`\b \f \n \r \t`, otherwise lowercase `\u00xx`) and lone surrogates. `/` and non-ASCII characters are not escaped.
3. Encode as UTF-8.

`canonicalPayloadHash` is the lowercase hex SHA-256 of these bytes.

## Signature

ECDSA over P-256 with SHA-256, computed over the canonical bytes (not over the hash). Accepted encodings, declared in `signatureFormat`:

- `der`: ASN.1 `ECDSA-Sig-Value` in its canonical (minimal) encoding, as produced by Android Keystore and iOS `SecKeyCreateSignature`. Other encodings of the same values are refused.
- `raw`: `r || s`, 64 bytes, as produced by WebCrypto and some HSMs.

Auth Core allows 5 signature attempts per authorization. The default lifetime is 120 seconds; the bank may set it between 30 and 900 seconds. A verified authorization is consumed atomically and cannot be used again.

## Device-side verification ("what you see is what you sign")

Before displaying or signing, the SDK:

1. decodes `canonicalPayloadBase64` and parses it strictly. The bytes are accepted only if re-encoding the parsed object reproduces them exactly. This rejects duplicate keys, alternative escapes, whitespace, unsorted keys and trailing data;
2. requires exactly the 15 fields, the protocol constants and valid formats, and no control, format or separator characters in any string;
3. checks `canonicalPayloadHash`;
4. requires every displayed response field (amount, currency, beneficiary, reference, expiry and the others) to equal the value in the signed bytes;
5. renders the confirmation screen and the biometric prompt only from the signed bytes.

### Confirmation text

Both SDKs build the same text from the signed bytes (checked against `confirmation_text` in `test-vectors/signed-payload-v1.json`):

```
<amount> <currency> → <beneficiary display>
<operation_type> • <transaction_reference>
```

The beneficiary display joins values with ` · ` in this order: the account identifier first (the first present of `iban`, `account`, `account_number`), then `name`, then `bic`, then the remaining keys in sorted order. The account comes first because the system biometric prompt has limited room and may truncate the end of the text; a name must not push the account out of view. With values limited to 140 characters, the account is always in the first line. Whether the whole text is visible depends on the platform prompt and is checked on devices (`docs/engineering/DEVICE_ACCEPTANCE_CHECKLIST.md`); the host app's own confirmation screen must show every field in full.

Any mismatch refuses signing with a reason code: `invalid_json`, `duplicate_key`, `not_canonical`, `missing_field`, `unexpected_field`, `invalid_value`, `wrong_protocol` or `response_mismatch`. `approve()` also refuses an authorization whose `credential_id` is not the device's own (`wrong_device`).

## Amount display

Minor units are converted with integer string arithmetic, never floating point, using the ISO 4217 minor-unit count of the currency. The SDKs carry a fixed table rather than the platform's currency data, which follows CLDR and differs from ISO 4217 for some currencies ([ADR 0007](../adr/0007-iso-4217-minor-units-table.md)):

| Minor units | Currencies |
|---|---|
| 0 | BIF, CLP, DJF, GNF, ISK, JPY, KMF, KRW, PYG, RWF, UGX, UYI, VND, VUV, XAF, XOF, XPF |
| 3 | BHD, IQD, JOD, KWD, LYD, OMR, TND |
| 4 | CLF, UYW |
| 2 | every other code |

## Example

`auth-core/test-vectors/authorization-v1-example.json` contains a complete object with its canonical bytes and hash. `auth-core/test/protocol.test.mjs` signs it with a P-256 key and verifies it through the server code.
