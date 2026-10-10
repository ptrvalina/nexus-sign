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

## Architecture

- [Adaptive verification](architecture/adaptive-verification.md): PUSH, AUDIO and VIDEO escalation
- [Lifecycle state machines](architecture/state-machines.md): authorization, bank transaction, credential and identity transitions enforced by the database
- [Device replacement](architecture/device-replacement.md): moving an enrolled identity to a new device with the bank's replacement authorization
- [Architecture decision records](adr/README.md), including [0016](adr/0016-remove-compatibility-paths.md) removal of compatibility paths and unused schema

## Security

- [Threat model](security/threat-model.md): production requirements, invariants, trust boundaries, threats and controls with their tests, residual risks
- [Device attestation](security/attestation.md): App Attest, Play Integrity, Android key attestation and its policy, status list
- [HSM and key management](security/hsm-key-management.md)

## Reference

- API contract: [openapi.yaml](../auth-core/openapi.yaml)
- [Error responses](reference/error-responses.md)
- [Data model](reference/data-model.md) and [database migrations](../auth-core/migrations/README.md)
- [Compatibility and versioning](compatibility-and-versioning.md)

## Operations

- [Deployment](operations/deployment.md)
- [Configuration reference](operations/configuration.md)
- [Monitoring](operations/monitoring.md)
- [Upgrade from 1.4.0 to 2.0](operations/upgrade-2.0.md)
- [Incident response](operations/incident-response.md)
- [Disaster recovery](operations/disaster-recovery.md)
- [Runbooks](operations/runbooks/README.md), including [Android attestation status list](operations/runbooks/android-attestation-status-list.md)
- [Release: verification status and checklist](operations/release.md)
