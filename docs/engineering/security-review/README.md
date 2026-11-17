# Internal security review, November 2026

Working reports of the internal review summarized in the [security assessment report](../SECURITY_ASSESSMENT_REPORT.md). They describe the code as it was **before** the fixes on branch `engineering/production-readiness`; the status of each finding is in the assessment report, not here. Paths such as `<review workspace>/` refer to the reviewers' scratch directory and are not part of the repository.

| Report | Area |
|---|---|
| [A1](A1_authorization_core.md) | Authorization core |
| [A2](A2_recovery_admin_channels_api.md) | Recovery, admin console, verification channels, API |
| [B](B_crypto_hsm_evidence.md) | Cryptography, HSM, evidence |
| [C](C_database_execution_boundary.md) | Databases and the bank execution boundary |
| [D](D_mobile_sdks.md) | Mobile SDKs |
| [E](E_docs_ci_tests_hygiene.md) | Documentation, CI and tests |
