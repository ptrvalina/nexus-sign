# Bank integration: execution boundary and payment gateway

This directory has three parts:

- the **contract** a bank backend implements so that no payment confirmed through NEXUS-SIGN reaches its payment provider without the bank's own trust check and the bank's own approval;
- the **state machine**, enforced by the bank's database;
- a **reference implementation**, tested with Auth Core on SoftHSM, PostgreSQL, the gateway in its own process behind mutual TLS, and a provider double:
  - `auth-core/test/integration/bank-execution-processes.test.mjs`;
  - `bank-execution-boundary.test.mjs`;
  - `bank-trust-compromise.test.mjs`.

It is not a bank backend, and it is not integrated with one. This repository has no core banking system and no payment provider. The provider double in the tests proves nothing about a real provider.

Pilot integration: [pilot execution pack](../docs/integration/pilot-execution-pack.md). States and transitions: [payment state machine](../docs/architecture/payment-state-machine.md). Why: [bank credential trust v1](../docs/protocol/bank-credential-trust-v1.md).

## Components and their authority

| Component | Runs as | May do | May not do |
|---|---|---|---|
| Execution boundary (`executionBoundary.mjs`, `trustStore.mjs`) | the bank's backend, database role *boundary* | read everything; write statements, trust rows, heads, payments; move executions through `CHECKING`, `APPROVED`, `HELD`, `REFUSED` and record provider answers | set `SUBMITTED`: the database refuses it from this role; change terms or an approved order; move a head back; leave a final state |
| Payment gateway (`paymentGateway.mjs`) | its own process, database role *gateway*, HTTPS with mutual TLS | call `bank_submit`, `bank_resubmit`, `bank_operation_for_lookup`; send the **stored** order to the provider; look payments up | read or write any table; send an order nobody approved, for another attempt, twice, or with other terms |
| Schema owner (`schema.mjs`, `installSchema`) | migrations only | owns the tables, the trigger and the `SECURITY DEFINER` functions | not used by any running service |
| Auth Core | outside the bank | answers about authorizations and evidence; sends webhooks | everything above: it holds no bank database credentials and no client certificate for the gateway |

Authority to send a payment is the `APPROVED` row in the bank's database, for one attempt ID and one order hash. It is not a token and not an object in memory. The phase 13 in-memory permit could be issued by any second instance, and any module holding the raw adapter bypassed it (reproduced). It is removed.

Caller authentication to the gateway uses mutual TLS with an allow-list of client certificate names: standard, no custom protocol. It is defence in depth. Even a caller with a valid certificate can only cause the payment that was already approved, with its stored order, to be sent once.

## Rules for the bank backend

1. **One entry point.** Every path that can move money for a NEXUS-SIGN payment calls `boundary.execute(paymentId)`:
   - operator actions, the API, retries, administrative tools;
   - the reconciliation job (`reconcileDue()`);
   - the webhook handler (`createAuthCoreWebhookHandler`). A webhook only asks the boundary: Auth Core holds the webhook secret, so a compromised Auth Core can sign any event.
2. **The provider only behind the gateway.** Only the gateway's process has the provider's credentials and network route. Only the boundary has the gateway's client certificate. The gateway's database role has no table rights.
3. **The bank's own data decides.** Terms are recorded at `CREATED` and are immutable. Statements are signed with the bank's trust key. The pinned evidence keys and bank trust keys are configuration. Heads are kept from `evidence.appended` and move forward only. Nothing is taken from an Auth Core answer as trust.
4. **The provider contract is declared, not assumed.** `providerCapabilities: { idempotentSubmit, lookup }` states what the bank's contract with the provider guarantees. Both default to false. Without them the boundary never resolves an unknown outcome automatically.

## API

```js
import { installSchema, createTrustStore, createExecutionBoundary, createAuthCoreClient,
  createGatewayClient, createPaymentGateway, createGatewayServer, createHttpProvider,
  createAuthCoreWebhookHandler } from './index.mjs';

await installSchema(ownerPool, { boundaryRole: 'bank_boundary', gatewayRole: 'bank_gateway' }); // migration

// gateway process
const gateway = createPaymentGateway({ pool: gatewayRolePool, provider: createHttpProvider({ url }) });
createGatewayServer({ gateway, tls: { key, cert, ca }, allowedClients: ['bank-execution-boundary'] }).listen(port);

// backend process(es)
const store = createTrustStore(boundaryRolePool, { bankTrustKeys });
const boundary = createExecutionBoundary({ store, authCore: createAuthCoreClient({ baseUrl, accessToken }),
  gateway: createGatewayClient({ url, tls: { key, cert, ca } }), evidenceKeys, bankTrustKeys,
  providerCapabilities: { idempotentSubmit: true, lookup: true } });
await store.createPayment({ paymentId, bankTransactionReference, terms });   // CREATED
await store.attachAuthorization(paymentId, authorizationId);                 // AWAITING_AUTHORIZATION
await boundary.execute(paymentId);   // EXECUTED | PROVIDER_FAILED | PENDING_PROVIDER | OUTCOME_UNKNOWN
                                     // | REVIEW | REFUSED | HELD | IN_PROGRESS | NOT_AUTHORIZED
await boundary.reconcileDue();       // job: every open or stopped payment
await boundary.audit(paymentId);     // compares a final state with the provider; a disagreement is a finding
await store.resolveReview(paymentId, 'succeeded' | 'failed', { operator, note });
```

## Provider contract the gateway expects

```text
POST /payments  { operationId, paymentId, reference, operationType, amountMinor, currency, beneficiary }
  -> { status: 'succeeded' | 'failed' | 'pending', providerReference }
GET  /payments/{operationId}
  -> 200 { status: 'succeeded' | 'failed' | 'pending', providerReference } | 404 (not found)
```

- `operationId` is the payment's `bankTransactionReference`: stable, unique, the same on every resubmission.
- `idempotentSubmit: true` means a second `POST` with the same `operationId` never moves money again.
- `lookup: true` means `GET` is authoritative for any `operationId` the provider may have received.

Anything else is unknown to the boundary.

## What is atomic, and what is not

- **Atomic in the bank's database:**
  - the claim;
  - the approval together with the final check, serialized with a revocation on the credential row;
  - the submission record (`APPROVED → SUBMITTED`);
  - `EXECUTED` together with the head.
- **Not atomic:** the database and the provider. Exactly-once execution needs the provider's idempotency and lookup. Without them a person settles the outcome (`REVIEW`).
- **Revocation after `APPROVED`** does not stop the payment; `revoke()` reports it.
