# Documentation

## Start here

- [Architecture overview](architecture/overview.md): components, authorization flow, responsibility split
- [Bank backend integration guide](integration/bank-backend-guide.md): the calls a bank backend makes, in the order a team builds them
- SDK guides: [iOS](../ios-sdk/README.md), [Android](../android-sdk/README.md)
- [Sandbox](../sandbox/README.md) for workshops and integration rehearsals
- [Glossary](glossary.md)

## Protocol specifications

[Overview](protocol/README.md). Shared test vectors: `auth-core/test-vectors/`.

- [Transaction authorization protocol v1](protocol/authorization-protocol-v1.md): signed bytes, canonical encoding, device-side verification
- [Device authentication and offline confirmation](protocol/device-authentication-and-offline-confirmation.md): device-signed requests, QR confirmation without network
- [Recovery protocol 2](protocol/recovery-protocol-v2.md): recovery key wrapped under the phrase, setup, proof, attempt limits, threat analysis
- [Secure push](protocol/secure-push.md): push modes BANK and NEXUS, messages sealed per device, delivery receipts
- [Evidence format](protocol/evidence-format.md): sealed evidence records and how to verify them offline
- [Offline confirmation v2, deferred signature](protocol/offline-confirmation-v2-deferred-signature.md): the device signature that follows an offline code
- [Bank credential trust v1](protocol/bank-credential-trust-v1.md): the bank's signed approval and revocation of device keys
- [Verification result v1](protocol/verification-result-v1.md): signed results of audio and video verification

## Architecture

- [Adaptive verification](architecture/adaptive-verification.md): PUSH, AUDIO and VIDEO escalation
- [Lifecycle state machines](architecture/state-machines.md): authorization, bank transaction, credential and identity transitions enforced by the database
- [Device replacement](architecture/device-replacement.md): moving an enrolled identity to a new device with the bank's replacement authorization
- [Conversations with the bank](architecture/customer-conversations.md): chat, the bank's bot and the handover to an operator
- [Calls the customer starts](architecture/customer-calls.md)
- [Bank trust boundary](architecture/bank-trust-boundary.md) and [payment state machine](architecture/payment-state-machine.md): what the bank verifies before it executes a payment
- [Architecture decision records](adr/README.md), including [0016](adr/0016-remove-compatibility-paths.md) removal of compatibility paths and unused schema

## Security

- [Threat model](security/threat-model.md): production requirements, invariants, trust boundaries, threats and controls with their tests, residual risks
- [Device attestation](security/attestation.md): App Attest, Play Integrity, Android key attestation and its policy, status list
- [HSM and key management](security/hsm-key-management.md)
- [Bank database authorization](security/bank-database-authorization.md): signature, key and window checks inside the bank database
- [Offline confirmation threat model](security/offline-confirmation-threat-model.md)

## Reference

- API contract: [openapi.yaml](../auth-core/openapi.yaml)
- [Error responses](reference/error-responses.md)
- [Data model](reference/data-model.md) and [database migrations](../auth-core/migrations/README.md)
- [Compatibility and versioning](compatibility-and-versioning.md)

## Operations

- [Deployment](operations/deployment.md)
- [Configuration reference](operations/configuration.md)
- [Database migrations](operations/database-migrations.md): ledger, fresh install, upgrade, rollback
- [Monitoring](operations/monitoring.md)
- [Upgrade from 1.4.0 to 2.0](operations/upgrade-2.0.md)
- [Incident response](operations/incident-response.md)
- [Disaster recovery](operations/disaster-recovery.md)
- [Runbooks](operations/runbooks/README.md), including [Android attestation status list](operations/runbooks/android-attestation-status-list.md)
- [Release: verification status and checklist](operations/release.md)
- [Audio and video calls](operations/audio-video-calls.md)
- [Bank console: customers' mandates and devices](operations/bank-console.md)
- [Bank HSM acceptance procedure](operations/hsm-acceptance.md)

## Integration

- [Pilot execution pack](integration/pilot-execution-pack.md): what a bank pilot sets up, tests and signs off

## Engineering status and reports

Current status (fourth cycle, from CI runs):

- [Engineering readiness](engineering/ENGINEERING_READINESS.md): final report A–O and the decision
- [Release blockers](engineering/RELEASE_BLOCKERS.md), with the test protocol for each external check
- [CI validation](engineering/CI_VALIDATION.md): every CI job, run IDs, commands
- [SDK validation](engineering/SDK_VALIDATION.md): iOS and Android builds and tests
- [HSM validation](engineering/HSM_VALIDATION.md): the eight HSM suites on SoftHSM 2.7.0
- [Security findings](engineering/SECURITY_FINDINGS.md): findings register and threat model of ten scenarios
- [Functional completeness matrix](engineering/FUNCTIONAL_COMPLETENESS_MATRIX.md): the 44 software functions (49 items) against code and tests
- [Pilot readiness matrix](engineering/PILOT_READINESS_MATRIX.md): the 20 pilot conditions
- [Technical debt](engineering/TECHNICAL_DEBT.md)
- [Known limitations](engineering/KNOWN_LIMITATIONS.md)

Architecture and method:

- [Functional specification](engineering/FUNCTIONAL_SPECIFICATION.md)
- [Cryptographic architecture](engineering/CRYPTOGRAPHIC_ARCHITECTURE.md)
- [Security architecture](engineering/SECURITY_ARCHITECTURE.md)
- [Security testing guide](engineering/SECURITY_TESTING_GUIDE.md)
- [Security assessment report](engineering/SECURITY_ASSESSMENT_REPORT.md): findings of the internal review and how each was handled
- [Engineering quality review](engineering/ENGINEERING_QUALITY_REVIEW.md)
- [Decision log](engineering/DECISION_LOG.md), [key management](engineering/KEY_MANAGEMENT.md), [native build guide](engineering/NATIVE_BUILD_GUIDE.md), [device acceptance checklist](engineering/DEVICE_ACCEPTANCE_CHECKLIST.md), [third-party media](engineering/THIRD_PARTY_MEDIA.md)

Records of earlier cycles (numbers as of their date):

- [Final readiness package (A–J), third cycle](engineering/FINAL_READINESS_PACKAGE.md)
- [Final engineering report, first and second cycles](engineering/FINAL_ENGINEERING_REPORT.md)
