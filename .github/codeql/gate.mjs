// CodeQL result gate. Lists every result in the SARIF files of the given
// directory with its security severity, and fails when a result of severity
// 7.0 or higher is not covered by an entry in reviewed-findings.tsv. Entries
// are matched by rule ID and a regular expression on the file path; an entry
// that matches no result is reported so the list does not go stale.
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const dir = process.argv[2] ?? 'codeql-results';
const reviewedFile = join(fileURLToPath(new URL('.', import.meta.url)), 'reviewed-findings.tsv');
const THRESHOLD = 7.0;

const reviewed = readFileSync(reviewedFile, 'utf8').split('\n')
  .map((line) => line.trim())
  .filter((line) => line && !line.startsWith('#'))
  .map((line) => {
    const [rule, path, reason] = line.split('\t');
    if (!rule || !path || !reason) throw new Error(`reviewed-findings.tsv: rule, path and reason are required: ${line}`);
    return { rule, path: new RegExp(path), reason, used: 0 };
  });

const findings = [];
for (const name of readdirSync(dir).filter((f) => f.endsWith('.sarif'))) {
  const sarif = JSON.parse(readFileSync(join(dir, name), 'utf8'));
  for (const run of sarif.runs ?? []) {
    const rules = [...(run.tool?.driver?.rules ?? []), ...(run.tool?.extensions ?? []).flatMap((e) => e.rules ?? [])];
    const severity = new Map(rules.map((r) => [r.id, Number(r.properties?.['security-severity'] ?? 0)]));
    for (const result of run.results ?? []) {
      const location = result.locations?.[0]?.physicalLocation;
      findings.push({
        rule: result.ruleId,
        severity: severity.get(result.ruleId) ?? 0,
        path: location?.artifactLocation?.uri ?? '',
        line: location?.region?.startLine ?? 0,
        message: (result.message?.text ?? '').split('\n')[0],
      });
    }
  }
}

findings.sort((a, b) => b.severity - a.severity || a.path.localeCompare(b.path) || a.line - b.line);
let open = 0;
for (const f of findings) {
  let status = 'below threshold';
  if (f.severity >= THRESHOLD) {
    const entry = reviewed.find((r) => r.rule === f.rule && r.path.test(f.path));
    if (entry) { entry.used += 1; status = 'reviewed'; } else { open += 1; status = 'OPEN'; }
  }
  console.log(`${f.severity.toFixed(1)}\t${status}\t${f.rule}\t${f.path}:${f.line}\t${f.message}`);
}
for (const r of reviewed.filter((entry) => entry.used === 0)) {
  console.log(`note: reviewed entry matches no result and can be removed: ${r.rule} ${r.path.source}`);
}
console.log(`results: ${findings.length}; severity >= ${THRESHOLD} not reviewed: ${open}`);
process.exit(open === 0 ? 0 : 1);
