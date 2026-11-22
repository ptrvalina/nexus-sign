# NEXUS-SIGN sandbox: demonstration bank

An isolated environment that shows NEXUS-SIGN working inside a bank. The bank app on the customer's phone, the bank's backend and ledger, and the bank's operations console all follow the same transactions, and every confirmation goes through the real Auth Core and the real SDKs. Everything here uses test funds and invented customers. It is not a bank.

It replaces the earlier Python sandbox, which had its own implementation of the protocol. This one contains no protocol or cryptography code of its own.

## What runs

| Service | Built from | Role |
|---|---|---|
| `auth-core` | `auth-core/` of this checkout, **unchanged**, plus SoftHSM 2.7.0 (`images/auth-core.Dockerfile`) | Auth Core in development mode. Evidence is sealed with a P-256 key on a SoftHSM token: a **test HSM**, not a production HSM |
| `postgres` | `postgres:16-alpine` with the unchanged `auth-core/src/db/schema.sql` and `scripts/db/roles.sql` | Auth Core's sandbox database `nexus_sign_sandbox`, with its own credentials |
| `redis` | `redis:7-alpine`, nothing persisted | Auth Core's sandbox Redis |
| `bank` | `bank/` (Node.js standard library only) | The demo bank: customers, accounts, cards, double-entry ledger, commission, idempotency, notifications, receipts, audit log (its own SQLite database), the bank app API, the operations console, the scenario engine |

PostgreSQL, Redis and Auth Core are on an internal Docker network with no route out, and they publish no port. Only the bank publishes ports: the console on `127.0.0.1:8190` and the device port on `127.0.0.1:8191`.

## Run

Requirements: Docker with Compose v2, `openssl`, `git`, Node.js 22.13 or later (only for `scenarios` and the tests).

```bash
sandbox/bin/sandbox up          # checks isolation, builds, starts, prints the console address and passwords
sandbox/bin/sandbox scenarios   # runs every demonstration scenario and prints the results
sandbox/bin/sandbox down        # stops; the data is kept
sandbox/bin/sandbox reset       # deletes the sandbox's data volumes; the next 'up' starts with fresh demo data
sandbox/bin/sandbox remove --yes  # deletes the sandbox's containers, volumes, images and sandbox/.state/
```

The first `up` builds SoftHSM and Auth Core, which takes a few minutes. `bin/sandbox` acts only on the Compose project `nexus-sign-sandbox` and on `sandbox/.state/`. It changes no global setting, no other project and no file outside `sandbox/`.

### Secrets

`up` creates `sandbox/.state/` (git-ignored, mode 700) on first use. It holds the sandbox's database passwords, its Auth Core encryption keys and SoftHSM PINs, the console password and the demo customers' password. They are random, belong to this sandbox only, and are never overwritten. The bank's OAuth client secret is created inside the sandbox when it first starts, and is passed to the bank on a private volume.

### Isolation checks (`sandbox/bin/sandbox check`)

`up` stops if any of these fail:

- Auth Core runs with `NODE_ENV=development` and points at the sandbox database and Redis.
- The configuration contains no APNs, FCM, SMS or webhook endpoint.
- The Compose project is `nexus-sign-sandbox`, and no host path outside the repository is mounted.
- `auth-core/` is the revision recorded in `PINNED_AUTH_CORE` and has no uncommitted changes. Pass `--allow-unpinned` to run anyway; the console shows the revision. After verifying the sandbox with a new Auth Core revision, record it with `sandbox/bin/sandbox pin`.

The bank also refuses to start unless `SANDBOX_ENVIRONMENT=sandbox` is set, its Auth Core host is a sandbox host, and its database file is inside its data directory.

## Using it

**Console:** open `http://127.0.0.1:8190` and log in as `operator`; the password is printed by `up`. It has these modules:

- Overview
- Customers (with their devices in Auth Core and evidence-chain verification)
- Accounts and cards (the ledger always sums to zero)
- Transactions, each with a timeline built from recorded events
- Authorization sessions
- Notification delivery
- Evidence (the pinned seal keys and the bank's check of each record)
- Policies
- Audit log (append-only)
- System health
- Scenarios

**Bank app:** the device port serves two things:

- the app API, `/app/v1/*`: login, accounts, history, cards (freeze, block), favorites, products, notifications, quotes, payments with `Idempotency-Key`, cancellation, receipts, the waiting confirmation, and QR (offline) challenges;
- the Auth Core endpoints a device calls, forwarded byte for byte.

The native iOS and Android bank apps are milestones 2 and 3. Their visual reference is in `design/mockups/`. The demo customers are `anna` and `piotr`, with the password printed by `up`.

**iPhone on the same Wi-Fi:** the SDK requires HTTPS on any address other than localhost.

1. Run `sandbox/bin/sandbox cert <your computer's Wi-Fi IPv4>`.
2. Install `sandbox/.state/tls/ca.crt` on the iPhone and trust it.
3. Start with `SANDBOX_DEVICE_BIND=<that IP> sandbox/bin/sandbox up`.

## How a payment is executed

1. The app sends the order. The bank validates it (own account, IBAN, amount, limit, funds), calculates the commission, and records the transaction (`TRANSACTION_CREATED`). It does this idempotently per customer and `Idempotency-Key`.
2. The bank asks Auth Core for an authorization with the exact terms: reference, amount, currency, payee, and the commission as a signed payee field. It stores the canonical payload hash Auth Core returns (`CHALLENGE_GENERATED`).
3. The app picks up the request (`CHALLENGE_DELIVERED`). The SDK shows the signed terms and signs with the device key after biometrics.
4. The bank reads the result from Auth Core, server to server; nothing the phone reports is taken as proof. When Auth Core reports `VERIFIED` with `confirmed: true`, the bank:
   - fetches the sealed evidence (`EVIDENCE_RECEIVED`);
   - verifies the HSM seal with the key it pinned, the device signature, and the enrolment link. It uses Auth Core's independent verifier `auth-core/scripts/lib/evidence.mjs`, imported unchanged (`SIGNATURE_VERIFIED`);
   - compares every signed field and the canonical payload hash with its own record (`BINDING_VERIFIED`);
   - records the commit request in Auth Core and decides (`AUTHORIZATION_DECISION`).
5. The ledger entries, balances, receipt and events are written in one database transaction (`LEDGER_EXECUTED`, `RECEIPT_GENERATED`, `EVIDENCE_RECORDED`). The bank then reports the result to Auth Core. Only then does the app show the payment as done.

Any failed check ends the transaction as `FAILED` with no ledger entry. An offline code without the device's signature (`OFFLINE_PROVISIONAL`) is never executed.

## Scenarios

The scenario engine uses the same services as the app and the same Auth Core. A **software test device** plays the customer's side. It is the simulated device of Auth Core's own integration tests (`auth-core/test/integration/support/actors.mjs`, imported unchanged): node:crypto keys, enrolled as platform `OTHER` with security level `SOFTWARE_TEST_KEY`. It is used only for the scenario customer.

| Scenario | What it shows |
|---|---|
| successful-transfer | A transfer inside the bank is executed once |
| successful-payment | A payment to another bank is executed, with commission |
| invalid-signature | A signature with an unknown key is refused by Auth Core; nothing is executed |
| altered-transaction-data | A signature over altered terms is refused by Auth Core |
| expired-challenge | The request expires, and a late signature is refused |
| rejected-authorization | The customer declines ("not me") |
| cancelled-transaction | The bank cancels, and a later signature is refused |
| push-delivery-failure | The notification is lost (fault), and nothing is executed |
| network-interruption | The device's network drops (fault); a retry succeeds |
| duplicate-request | Same `Idempotency-Key` with another order: 409 |
| idempotent-retry | The same request again gives the same transaction and one ledger entry |
| qr-authorization | QR code, offline code entered at the bank, then the deferred signature; executed only after it |
| offline-authorization | As above with the device offline; the signature is delivered when the network returns |
| failed-verification | The bank's copy of the evidence is altered (fault); the bank refuses |
| evidence-validation | The customer's whole chain is verified with the pinned keys and the bank's stored head |
| audio-escalation, video-escalation | Milestone 4 (robot call, automatic escalation). Shown as not available; nothing is simulated |

Fault injection (`SANDBOX_FAULT_INJECTION=enabled`) exists only in the sandbox bank. It can only make a check fail, never make one pass. Auth Core and the SDKs have no fault switches.

## Not in this milestone

- **Native apps.** iOS and Android: milestones 2 and 3.
- **Push.** APNs needs a paid Apple Developer membership and FCM needs a Firebase project, so the app polls the bank instead. Delivery is recorded when the app picks up the request.
- **SMS fallback.** Auth Core has no SMS channel, so none is offered.
- **Audio and video escalation.** Milestone 4. Auth Core supports calls with a bank operator or a verification provider; automatic escalation and a robot provider are not built yet.
- **Webhooks.** The bank reconciles with Auth Core every second instead.

## Tests

```bash
cd sandbox/bank && npm test                 # unit tests, no dependencies (Auth Core replaced by a test-only stand-in)
node --test sandbox/tests/e2e.test.mjs      # against a running sandbox: real Auth Core, SoftHSM, every scenario
```

CI runs both: `sandbox / bank unit tests` and `sandbox / isolated stack end to end`.
