# Kubernetes manifests for Auth Core

Plain manifests a bank adapts to its cluster: no Helm, no Kustomize, so every line is visible in review. Values marked `CHANGE` are the bank's.

| File | What |
|---|---|
| `00-serviceaccount.yaml` | Service account without a Kubernetes API token |
| `10-configmap.yaml` | Non-secret settings in the production posture Auth Core requires at startup |
| `secret.example.yaml` | The keys of the two Secrets, **without values**; create them from the bank's secrets manager |
| `20-migrate-job.yaml` | `npm run migrate` (ledger, lock, forward-only) as the owner role; run once per release after a backup |
| `30-deployment.yaml` | Three replicas spread over zones; non-root user 10001, read-only root filesystem, no capabilities, RuntimeDefault seccomp; probes `/healthz` and `/readyz`; the Android attestation status list mounted read-only |
| `40-service.yaml` | ClusterIP service and a disruption budget of two |
| `50-networkpolicy.yaml` | Ingress from the gateway and monitoring only; egress to DNS, PostgreSQL, Redis, the HSM and the egress proxy only |

Not included, because they are the bank's: the mTLS gateway and WAF ([deployment](../../docs/operations/deployment.md#gateway)), PostgreSQL, Redis, the HSM client library and its network path, the job that refreshes the attestation status list, the secrets manager integration, and Prometheus scraping (`/metrics` needs `METRICS_BEARER_TOKEN`).

## Check

```sh
python3 deploy/kubernetes/check-manifests.py   # needs PyYAML and auth-core's node_modules (typescript)
```

It checks the security settings of every pod, that the probes use routes Auth Core serves on the port it listens on, that the user matches the image, that the Job runs the migrate script, that every variable is one Auth Core reads, and runs Auth Core's own `configurationErrors()` and `productionBlockers()` over the ConfigMap with random placeholders for the Secret keys. CI runs it.

## Not verified

The manifests have not been applied to a cluster in the review environment (no cluster, no `kubectl`), and the image has not been built there (no Docker daemon). The HSM client library, the network policy selectors and the resource sizes need the bank's environment.
