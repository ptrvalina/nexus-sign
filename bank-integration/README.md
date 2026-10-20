# Bank integration: execution boundary and payment gateway

This directory has three parts:

- the **contract** a bank backend implements so that no payment confirmed through NEXUS-SIGN reaches its payment provider without the bank's own trust check and the bank's own approval;
- the **state machine**, enforced by the bank's database;
- a **reference implementation**, tested with Auth Core on SoftHSM, PostgreSQL, the gateway in its own process behind mutual TLS, and a provider double:
  - `auth-core/test/integration/bank-execution-processes.test.mjs`;
  - `bank-execution-boundary.test.mjs`;
  - `bank-trust-compromise.test.mjs`;
  - `bank-db-authorization.test.mjs` (roles, functions, attacks on the database).

It is not a bank backend, and it is not integrated with one. This repository has no core banking system and no payment provider. The provider double in the tests proves nothing about a real provider.

Pilot integration: [pilot execution pack](../docs/integration/pilot-execution-pack.md). States and transitions: [payment state machine](../docs/architecture/payment-state-machine.md). Why: [bank credential trust v1](../docs/protocol/bank-credential-trust-v1.md).

## Components and their authority

The bank's database is in its own schema `bank`. **No application role has `INSERT`, `UPDATE`, `DELETE`, `TRUNCATE` or any sequence right.** Every change is a call of a `SECURITY DEFINER` function of the schema owner, and each role may execute only its own. Details, the privilege matrix and every function: [bank database authorization](../docs/security/bank-database-authorization.md).

| Component | Runs as | May do | May not do |
|---|---|---|---|
| Execution boundary (`executionBoundary.mjs`, `trustStore.mjs`) | the bank's backend, database role *boundary* | read payments, executions, the log, statements, heads, findings; call `create_payment`, `attach_authorization`, `claim`, `approve`, `refuse`, `hold`, `mark_unknown`, `mark_review`, `keep_head`, `add_finding` | write any table; approve without `bank.approve` and its checks; choose the credential or the order hash of an approval; submit; record a provider's answer; change the registry; resolve a review |
| Payment gateway (`paymentGateway.mjs`) | its own process, database role *gateway*, HTTPS with mutual TLS | call `submit_basis`, `submit`, `resubmit`, `gateway_refuse`, `report`, `operation_for_lookup`; check the approval again (pinned evidence keys, bank trust keys, stored evidence, registry as at the approval); send the **stored** order; record the provider's answers | read any table; send an order nobody approved, for another attempt, twice, with other terms or on forged evidence; change the registry or trust |
| Registry service (`registry.mjs`, `createRegistry`) | database role *registry* | verify the bank's signature on a statement, then call `approve_credential`, `revoke_credential` | touch payments or executions; read tables |
| Operator tools (`createOperatorTools`) | database role *operator*, one login per person | read payments, executions, the log, findings; call `resolve_review` | anything else; name someone else as the resolver |
| Schema owner (`schema.mjs`, `installSchema`) | migrations only | owns the schema, the tables, the triggers and the functions | not used by any running service; see the residual risk below |
| Auth Core | outside the bank | answers about authorizations and evidence; sends webhooks | everything above: it holds no bank database credentials and no client certificate for the gateway |

Authority to send a payment is the `APPROVED` row in the bank's database, for one attempt ID and one order hash, together with the confirmation evidence stored with it. The gateway checks that evidence again before it sends. A holder of the boundary's database role alone cannot get a payment sent without a valid customer confirmation for exactly those terms with a key the bank approved (DA «forged evidence»).

Caller authentication to the gateway uses mutual TLS with an allow-list of client certificate names: standard, no custom protocol. It is defence in depth. Even a caller with a valid certificate can only cause the payment that was already approved, with its stored order, to be sent once.

**Residual boundary.** The schema owner and the PostgreSQL superuser can change or disable any of this: triggers, functions, grants, rows. That is not a property the database can remove from them. It is an operational control: the owner is used only for migrations under change control and dual control; its use, `ALTER`, `DISABLE TRIGGER`, `GRANT` and `SET ROLE` are logged and alerted outside the database; the privilege matrix is compared after every migration ([pilot execution pack](../docs/integration/pilot-execution-pack.md), sections 4 and 10).

## Rules for the bank backend

1. **One entry point.** Every path that can move money for a NEXUS-SIGN payment calls `boundary.execute(paymentId)`:
   - operator actions, the API, retries, administrative tools;
   - the reconciliation job (`reconcileDue()`);
   - the webhook handler (`createAuthCoreWebhookHandler`). A webhook only asks the boundary: Auth Core holds the webhook secret, so a compromised Auth Core can sign any event.
2. **The provider only behind the gateway.** Only the gateway's process has the provider's credentials and network route. Only the boundary has the gateway's client certificate. The gateway's database role has no table rights and records outcomes only for the attempt it submitted.
3. **The bank's own data decides.** Terms are recorded at `CREATED` and are immutable. Statements are signed with the bank's trust key. The pinned evidence keys and bank trust keys are configuration. Heads are kept from `evidence.appended` and move forward only. Nothing is taken from an Auth Core answer as trust.
4. **The provider contract is declared, not assumed.** `providerCapabilities: { idempotentSubmit, lookup }` states what the bank's contract with the provider guarantees. Both default to false. Without them the boundary never resolves an unknown outcome automatically.
5. **One database login per component and per operator.** The log records the login role (`session_user`), not a name the caller passes. A shared login makes the log useless for attribution.

## API

```js
import { installSchema, DATABASE_HARDENING, privilegeMatrix, intendedPrivileges, createTrustStore, createRegistry,
  createOperatorTools, createExecutionBoundary, createAuthCoreClient, createGatewayClient, createPaymentGateway,
  createGatewayServer, createHttpProvider, createAuthCoreWebhookHandler } from './index.mjs';

// database administrator, once: no temporary objects, nothing in public
await adminClient.query(DATABASE_HARDENING('bankdb'));
// migration, as the schema owner (not a superuser); revokes everything first, then grants each role its part
await installSchema(ownerPool, { boundary: 'bank_boundary', gateway: 'bank_gateway', registry: 'bank_registry', operator: 'bank_ops_anna' });
assert.deepEqual(await privilegeMatrix(ownerPool, roles), intendedPrivileges(roles));   // after every migration

// gateway process
const gateway = createPaymentGateway({ pool: gatewayRolePool, provider: createHttpProvider({ url }), evidenceKeys, bankTrustKeys });
createGatewayServer({ gateway, tls: { key, cert, ca }, allowedClients: ['bank-execution-boundary'] }).listen(port);

// registry service
const registry = createRegistry(registryRolePool, { bankTrustKeys });
await registry.approve(signedApproval, { head });     // verifies the bank's signature, then bank.approve_credential
const inFlight = await registry.revoke(signedRevocation);

// backend process(es)
const store = createTrustStore(boundaryRolePool);
const boundary = createExecutionBoundary({ store, authCore: createAuthCoreClient({ baseUrl, accessToken }),
  gateway: createGatewayClient({ url, tls: { key, cert, ca } }), evidenceKeys, bankTrustKeys,
  providerCapabilities: { idempotentSubmit: true, lookup: true } });
await store.createPayment({ paymentId, bankTransactionReference, terms });   // CREATED
await store.attachAuthorization(paymentId, authorizationId);                 // AWAITING_AUTHORIZATION
await boundary.execute(paymentId);   // EXECUTED | PROVIDER_FAILED | PENDING_PROVIDER | OUTCOME_UNKNOWN
                                     // | REVIEW | REFUSED | HELD | IN_PROGRESS | NOT_AUTHORIZED
await boundary.reconcileDue();       // job: every open or stopped payment
await boundary.audit(paymentId);     // compares a final state with the provider; a disagreement is a finding

// operator tools, with the operator's own login
await createOperatorTools(operatorPool).resolveReview(paymentId, 'succeeded' | 'failed', note);
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
  - the gateway's check of the approval together with the submission record (`APPROVED → SUBMITTED`), under the execution row's lock;
  - every transition together with its log row.
- **Not atomic any more (phase 15):** `EXECUTED` (recorded by the gateway) and the kept head (moved forward by the boundary afterwards).
- **Not atomic:** the database and the provider. Exactly-once execution needs the provider's idempotency and lookup. Without them a person settles the outcome (`REVIEW`).
- **Revocation after `APPROVED`** does not stop the payment; `revoke()` reports it. The gateway checks against the registry as it stood at the approval.
