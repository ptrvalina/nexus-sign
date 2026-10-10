## What and why

<!-- One or two sentences. Link the ticket. -->

## How it was tested

<!-- Commands run, devices used, or why no test applies. -->

## Checklist

- [ ] `CHANGELOG.md` updated under `## [Unreleased]`
- [ ] Protocol or vector change: vectors regenerated (`npm run generate:vectors`) and all four suites pass
- [ ] Security-relevant change: threat model and the matching page in `docs/security/` updated
- [ ] Database change: migration added and `src/db/schema.sql` updated to match
- [ ] Public API change: `openapi.yaml` and SDK READMEs updated
