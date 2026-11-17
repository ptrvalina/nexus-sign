# Protocol specifications

| Document | What it specifies |
|---|---|
| [Transaction authorization protocol v1](authorization-protocol-v1.md) | The signed authorization object, its canonical encoding and the device-side checks |
| [Device authentication and offline confirmation](device-authentication-and-offline-confirmation.md) | Device keys, device-signed requests, offline confirmation codes |
| [Offline confirmation v2](offline-confirmation-v2-deferred-signature.md) | Deferred device signature: QR `NXS2.`, upload, provisional and unsigned states, evidence `OFFLINE_SIGNED` |
| [Recovery protocol 2](recovery-protocol-v2.md) | Recovery key wrapping, setup, proof, attempt limits and threat analysis |
| [Secure push](secure-push.md) | Push modes, per-device sealing of messages, delivery receipts |
| [Evidence format](evidence-format.md) | Sealed evidence records, chain rules and offline verification |
| [Bank credential trust v1](bank-credential-trust-v1.md) | The bank's signed approval of each device key, revocations, and the bank's own execution decision, independent of Auth Core |
| [Verification result v1](verification-result-v1.md) | Signed results of audio and video verification from a bank operator or an external provider, bound to the session, the authorization and the device |
| [Payment mandates v1](payment-mandates-v1.md) | Signed recurring payment mandates, debit checks in Auth Core and the database, mandate evidence |

Shared test vectors for all of them are in `auth-core/test-vectors/`.
