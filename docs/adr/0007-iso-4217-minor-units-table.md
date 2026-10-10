# 0007. Fixed ISO 4217 minor-unit table in the SDKs

## Status

Accepted

## Date

2026-09-30

## Context

The signed bytes carry `amount_minor` as an integer string and `currency` as an ISO 4217 code. The SDK turns them into the amount the customer confirms, for example `125000` PLN into `1250.00`. The number of fraction digits must be the ISO 4217 minor unit of the currency, because that is what the bank's core system uses for `amount_minor`.

Platform currency APIs (`java.util.Currency` on Android, `NumberFormatter` on iOS) follow CLDR, which differs from ISO 4217 for several currencies, for example RSD and IQD. A wrong digit count shifts the decimal point on the confirmation screen and in the biometric prompt by a factor of 10 or more, and the result also depends on the OS version.

## Decision

- Both SDKs use the same fixed table (`SignedPayload.fractionDigits` in `SignedTransaction.kt` and `SignedTransaction.swift`):

  | Minor units | Currencies |
  |---|---|
  | 0 | BIF CLP DJF GNF ISK JPY KMF KRW PYG RWF UGX UYI VND VUV XAF XOF XPF |
  | 3 | BHD IQD JOD KWD LYD OMR TND |
  | 4 | CLF UYW |
  | 2 | every other code |

- Amounts are formatted with integer string arithmetic, never floating point (`formatMinorUnits`).

## Consequences

- iOS and Android show the same amount for the same signed bytes on every OS version.
- A change in ISO 4217 needs an SDK release; the table is not updated by the platform.
- An unknown or new code is shown with 2 digits.
- The table is pinned by the `amount_formatting` vectors in `signed-payload-v1.json` and by the per-currency assertions (PLN, JPY, KWD, RSD, IQD, CLF) in Android `SignedTransactionTest` "amounts are formatted with integer arithmetic" and iOS `testAmountsAreFormattedWithIntegerArithmetic`.
