# Security policy

## Reporting a vulnerability

Report security issues privately: to the security contact of the organization that operates the deployment, or to Nexis Trust Technologies AG through the channel named in your support agreement. Do not open a public issue and do not disclose exploitable details before a coordinated fix is agreed.

Include the affected component and version (`VERSION`), steps to reproduce, and the impact you observed. Remove tokens, keys and customer data from logs before sending them.

## Supported versions

Security fixes are made on the latest minor release. See [docs/compatibility-and-versioning.md](docs/compatibility-and-versioning.md) for how older SDK versions are handled.

## Scope

In scope: Auth Core, the iOS and Android SDKs, the authorization and device protocols, credential lifecycle and recovery, adaptive verification, evidence sealing, and the deployment controls described in the documentation.

The sandbox (`sandbox/`) is a demonstration environment with test funds and invented customers, running the unchanged Auth Core with a SoftHSM test HSM. It is out of scope for production security claims; issues in it are still welcome.

## References

- [Threat model](docs/security/threat-model.md)
- [Release checklist](docs/operations/release.md), including the controls a production deployment needs
