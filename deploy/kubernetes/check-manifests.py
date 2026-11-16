#!/usr/bin/env python3
"""Checks the Kubernetes manifests against Auth Core itself (PyYAML only).

1. Every document parses and has apiVersion, kind and metadata.name.
2. Containers run as a fixed non-root user, without privilege escalation,
   with a read-only root filesystem, all capabilities dropped and the
   RuntimeDefault seccomp profile; no service account token is mounted.
3. Probes use the routes app.ts serves (/healthz, /readyz) on the port the
   container exposes, which is PORT; the image's USER is the runAsUser.
4. The migration Job runs the `migrate` script of package.json.
5. Every ConfigMap and Secret key is a variable env.ts reads.
6. Auth Core's own startup checks, configurationErrors() and
   productionBlockers() from src/config/productionPosture.ts, pass for the
   ConfigMap plus placeholder values for the Secret keys (posture.mjs).
This does not apply anything to a cluster.
"""
import json
import os
import re
import subprocess
import sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
CORE = os.path.join(HERE, '..', '..', 'auth-core')
problems = []

docs = []
for name in sorted(os.listdir(HERE)):
    if name.endswith('.yaml'):
        with open(os.path.join(HERE, name), encoding='utf-8') as f:
            for d in yaml.safe_load_all(f):
                if d is None:
                    continue
                if not all(k in d for k in ('apiVersion', 'kind', 'metadata')) or 'name' not in d['metadata']:
                    problems.append(f'{name}: a document without apiVersion, kind or metadata.name')
                docs.append((name, d))

env_ts = open(os.path.join(CORE, 'src/config/env.ts'), encoding='utf-8').read()
env_keys = set(re.findall(r'^\s+([A-Z][A-Z0-9_]+):\s*(?:z\b|optional\(|$)', env_ts, re.M))
app_ts = open(os.path.join(CORE, 'src/app.ts'), encoding='utf-8').read()
routes = set(re.findall(r"app\.get\('(/[a-z]+)'", app_ts))
dockerfile = open(os.path.join(CORE, 'Dockerfile'), encoding='utf-8').read()
image_user = re.search(r'^USER (\d+):(\d+)$', dockerfile, re.M)
package = json.load(open(os.path.join(CORE, 'package.json'), encoding='utf-8'))

config = {}
secret_keys = []
for name, d in docs:
    kind = d['kind']
    if kind == 'ConfigMap':
        config.update({k: str(v) for k, v in d['data'].items()})
    if kind == 'Secret':
        if any(v for v in (d.get('stringData') or {}).values()) or d.get('data'):
            problems.append(f'{name}: the example Secret must not carry values')
        if d['metadata']['name'] == 'nexus-auth-core-secrets':
            secret_keys = list(d['stringData'].keys())
    for key in list((d.get('data') or {}).keys()) + list((d.get('stringData') or {}).keys()):
        if kind in ('ConfigMap', 'Secret') and key not in env_keys:
            problems.append(f'{name}: {key} is not a variable of env.ts')
    pod = d['spec']['template']['spec'] if kind in ('Deployment', 'Job') else None
    if pod is None:
        continue
    if pod.get('automountServiceAccountToken') is not False:
        problems.append(f'{name}: automountServiceAccountToken must be false')
    psc = pod.get('securityContext', {})
    if psc.get('runAsNonRoot') is not True or psc.get('seccompProfile', {}).get('type') != 'RuntimeDefault':
        problems.append(f'{name}: pod must set runAsNonRoot and the RuntimeDefault seccomp profile')
    if not image_user or str(psc.get('runAsUser')) != image_user.group(1) or str(psc.get('runAsGroup')) != image_user.group(2):
        problems.append(f'{name}: runAsUser/runAsGroup must equal the image USER ({image_user.group(0) if image_user else "none"})')
    for c in pod['containers']:
        sc = c.get('securityContext', {})
        if sc.get('allowPrivilegeEscalation') is not False or sc.get('readOnlyRootFilesystem') is not True or sc.get('capabilities', {}).get('drop') != ['ALL']:
            problems.append(f'{name}/{c["name"]}: no privilege escalation, read-only root filesystem and all capabilities dropped')
        if 'limits' not in c.get('resources', {}) or 'memory' not in c['resources']['limits']:
            problems.append(f'{name}/{c["name"]}: a memory limit is required')
        ports = {p['name']: p['containerPort'] for p in c.get('ports', [])}
        for probe in ('startupProbe', 'livenessProbe', 'readinessProbe'):
            if probe in c:
                get = c[probe]['httpGet']
                if get['path'] not in routes:
                    problems.append(f'{name}: {probe} path {get["path"]} is not served by app.ts')
                if ports.get(get['port']) != int(config.get('PORT', '8080')):
                    problems.append(f'{name}: {probe} port is not PORT')
        if kind == 'Deployment' and not all(p in c for p in ('livenessProbe', 'readinessProbe')):
            problems.append(f'{name}: liveness and readiness probes are required')
        if kind == 'Job' and c.get('command') != ['node', package['scripts']['migrate'].split()[1]] and ' '.join(c.get('command', [])) != package['scripts']['migrate']:
            problems.append(f'{name}: the Job must run `{package["scripts"]["migrate"]}`')

if not problems:
    result = subprocess.run(['node', os.path.join(HERE, 'posture.mjs')], input=json.dumps({'config': config, 'secretKeys': secret_keys}),
                            capture_output=True, text=True, cwd=CORE)
    if result.returncode != 0:
        problems.append(f'posture: {result.stdout.strip()} {result.stderr.strip()}')
    else:
        print(result.stdout.strip())

for p in problems:
    print(p)
if problems:
    sys.exit(1)
print(f'ok: {len(docs)} Kubernetes documents follow Auth Core (probes, user, migration, variables, production posture)')
