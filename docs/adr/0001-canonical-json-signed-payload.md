# 0001. Sorted-key JSON as the signed payload form

## Status

Accepted

## Date

2026-09-26

## Context

The customer's device signs one byte string per transaction. Auth Core, the iOS SDK, the Android SDK, the sandbox and an auditor's offline verifier must produce or check exactly the same bytes, and the device must be able to show the customer what those bytes say. Candidates were RFC 8785 (JSON Canonicalization Scheme), deterministic CBOR, and JSON with sorted keys as produced by `JSON.stringify`.

The authorization object contains only strings and one flat object of strings (`beneficiary`). Amounts are integer decimal strings and timestamps are RFC 3339 strings, so no floating-point numbers occur. For such values, recursively sorted keys in UTF-16 code-unit order with `JSON.stringify` escaping give the same bytes as RFC 8785; the two differ only in number serialization, which the protocol excludes.

`JSON.stringify` enumerates integer-like keys (`"0"`, `"10"`) before other keys, regardless of the sort. Auth Core would then emit bytes that a sorted-key encoder on another platform cannot reproduce.

## Decision

- The signed form is the v1 authorization object with keys sorted recursively, serialized with `JSON.stringify` semantics and encoded as UTF-8 (`canonicalizeAuthorization` in `auth-core/src/services/canonicalAuthorization.ts`).
- Beneficiary keys must match `^[a-z][a-z0-9_]{0,63}$`, at most 16 fields, values up to 512 characters (reduced to 140, without leading or trailing space, in 2.0.0; ).
- Each SDK parses the bytes with its own strict reader and accepts them only if re-encoding the parsed object reproduces them byte for byte (`SignedPayload.parse` in `SignedTransaction.kt` and `SignedTransaction.swift`). This rejects duplicate keys, alternative escapes, whitespace, unsorted keys and trailing data.
- No RFC 8785 or CBOR library is added. Auth Core keeps its CBOR dependency only for App Attest attestation objects.
- The shared vectors in `auth-core/test-vectors/signed-payload-v1.json` pin all implementations; `check-signed-payload-vectors.mjs` compares them with the server code and with the copies bundled in each test suite.

## Consequences

- An auditor reads amount, currency, beneficiary and expiry directly from `signedPayloadBase64` in the evidence record; no decoder beyond JSON is needed.
- The iOS SDK has no third-party dependency for parsing; the Android SDK uses its own reader for the signed bytes.
- Every implementation carries a small canonical encoder that must match `JSON.stringify` escaping exactly. The vectors cover unicode, quotes, backslash and slash, and the escaped-slash and whitespace rejections.
- Adding a number-valued field, or a key outside the beneficiary pattern, needs a new protocol version.
- The specification is in [authorization-protocol-v1.md](../protocol/authorization-protocol-v1.md).
