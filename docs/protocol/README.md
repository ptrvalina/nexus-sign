# Protocol specifications

| Document | What it specifies |
|---|---|
| [Transaction authorization protocol v1](authorization-protocol-v1.md) | The signed authorization object, its canonical encoding and the device-side checks |
| [Device authentication and offline confirmation](device-authentication-and-offline-confirmation.md) | Device keys, device-signed requests, offline confirmation codes |
| [Recovery protocol 2](recovery-protocol-v2.md) | Recovery key wrapping, setup, proof, attempt limits and threat analysis |
| [Secure push](secure-push.md) | Push modes, per-device sealing of messages, delivery receipts |
| [Evidence format](evidence-format.md) | Sealed evidence records, chain rules and offline verification |

Shared test vectors for all of them are in `auth-core/test-vectors/`.
