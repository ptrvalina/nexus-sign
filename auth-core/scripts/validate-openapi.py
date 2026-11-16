#!/usr/bin/env python3
"""Structural check of openapi.yaml (stdlib plus PyYAML and jsonschema).

check-openapi-routes.mjs compares the routes with the Express routers; this
script checks the document itself, which that check does not parse: the
YAML loads, every $ref resolves, every operation has responses and unique
operation-level parameters, every path parameter is declared, and every
schema is a valid JSON Schema (OpenAPI 3.0 `nullable` removed first).
Exits 1 with one line per problem.
"""
import re
import sys

import yaml
from jsonschema import Draft4Validator
from jsonschema.exceptions import SchemaError

METHODS = {'get', 'put', 'post', 'delete', 'patch', 'head', 'options'}
OPENAPI_ONLY = {'nullable', 'discriminator', 'readOnly', 'writeOnly', 'xml', 'externalDocs', 'example', 'deprecated'}


def main(path):
    with open(path, encoding='utf-8') as f:
        doc = yaml.safe_load(f)
    problems = []
    if not str(doc.get('openapi', '')).startswith('3.'):
        problems.append('openapi: not an OpenAPI 3 document')

    def resolve(ref):
        if not ref.startswith('#/'):
            return None
        node = doc
        for part in ref[2:].split('/'):
            if not isinstance(node, dict) or part not in node:
                return None
            node = node[part]
        return node

    def walk(node, where):
        if isinstance(node, dict):
            if '$ref' in node and resolve(node['$ref']) is None:
                problems.append(f'{where}: unresolved $ref {node["$ref"]}')
            for k, v in node.items():
                walk(v, f'{where}/{k}')
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f'{where}[{i}]')

    walk(doc, '#')

    def plain(schema):
        if isinstance(schema, dict):
            return {k: plain(v) for k, v in schema.items() if k not in OPENAPI_ONLY}
        if isinstance(schema, list):
            return [plain(v) for v in schema]
        return schema

    for name, schema in (doc.get('components', {}).get('schemas') or {}).items():
        try:
            Draft4Validator.check_schema(plain(schema))
        except SchemaError as e:
            problems.append(f'components/schemas/{name}: {e.message}')

    def param(p):
        return resolve(p['$ref']) or {} if isinstance(p, dict) and '$ref' in p else p

    for route, item in (doc.get('paths') or {}).items():
        declared = {param(p).get('name') for p in item.get('parameters', []) if param(p).get('in') == 'path'}
        for method, op in item.items():
            if method not in METHODS:
                continue
            where = f'{method.upper()} {route}'
            if not op.get('responses'):
                problems.append(f'{where}: no responses')
            params = [param(p) for p in op.get('parameters', []) if 'name' in param(p)]
            seen = [(p['in'], p['name']) for p in params]
            if len(seen) != len(set(seen)):
                problems.append(f'{where}: duplicate parameters')
            in_path = declared | {p['name'] for p in params if p['in'] == 'path'}
            for name in re.findall(r'{([^}]+)}', route):
                if name not in in_path:
                    problems.append(f'{where}: path parameter {name} is not declared')
            for code, response in op['responses'].items():
                body = response if '$ref' not in response else resolve(response['$ref']) or {}
                for media in (body.get('content') or {}).values():
                    schema = media.get('schema')
                    if schema is not None and '$ref' not in schema:
                        try:
                            Draft4Validator.check_schema(plain(schema))
                        except SchemaError as e:
                            problems.append(f'{where} {code}: {e.message}')

    for p in problems:
        print(p)
    if problems:
        sys.exit(1)
    print(f'ok: {path} is structurally valid ({len(doc["paths"])} paths, {len(doc["components"]["schemas"])} schemas)')


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else 'openapi.yaml')
