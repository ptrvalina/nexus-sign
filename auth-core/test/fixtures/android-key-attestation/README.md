# Android key attestation test chains

Real-device attestation chains, copied unchanged (leaf first) with their expected parsed values from
[android/keyattestation](https://github.com/android/keyattestation) `testdata/` at commit
`55c35040a1b5b72e6d63bfb150c5c68a175c1462` (Apache License 2.0):

| File | Upstream | Security level | Root |
|---|---|---|---|
| `frankel_sdk37_TEE_EC_2026.*` | `testdata/frankel/sdk37/TEE_EC_2026.{pem,json}` | TEE, attestation version 500 | ECDSA P-384 Key Attestation CA1 |
| `tegu_sdk36_SB_EC_2026_ROOT.*` | `testdata/tegu/sdk36/SB_EC_2026_ROOT.{pem,json}` | StrongBox, version 300 | ECDSA P-384 Key Attestation CA1 |
| `caiman_sdk36_TEE_EC_RKP.*` | `testdata/caiman/sdk36/TEE_EC_RKP.{pem,json}` | TEE, version 400, Remote Key Provisioning | RSA root D50FF25BA3F2D6B3 |

The chains contain short-lived RKP intermediates: tests verify them at the key's
`creationDateTime`, as the upstream tests do.

`status-example.json` is synthetic test data written for this repository in the format of Google's
attestation status list (https://android.googleapis.com/attestation/status, documented at
https://developer.android.com/privacy-and-security/security-key-attestation). It is not the live list;
its first entry is the serial of the TEE sample's RKP attestation certificate, so the revocation path is
exercised against a real chain.

`synthetic-path-chains.json` is synthetic test data written for this repository with OpenSSL: a test
root (not a Google root, passed to the verifier as `roots`) and four chains whose leaf carries a
KeyDescription claiming StrongBox, a locked bootloader and the test challenge. Three of them break the
certification path (an attested Keystore key as the issuer, an issuing CA without `keyCertSign`, a path
length constraint exceeded); the fourth is a well-formed control chain. The private keys were not kept.
