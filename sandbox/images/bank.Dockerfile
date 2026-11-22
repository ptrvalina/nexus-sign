# syntax=docker/dockerfile:1
# Sandbox bank: Node.js standard library only (no npm dependencies).
# It imports two files of this checkout unchanged: Auth Core's independent
# evidence verifier and the simulated device of Auth Core's tests (used only
# for the scenario customer). The repository layout is kept so the relative
# imports resolve as in a checkout. Build context: the repository root.
FROM node:22-alpine
WORKDIR /repo
COPY auth-core/scripts/lib/evidence.mjs auth-core/scripts/lib/evidence.mjs
COPY auth-core/test/integration/support/actors.mjs auth-core/test/integration/support/actors.mjs
COPY sandbox/config sandbox/config
COPY sandbox/bank/package.json sandbox/bank/package.json
COPY sandbox/bank/src sandbox/bank/src
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack \
 && addgroup -S -g 10002 bank && adduser -S -u 10002 -G bank bank && mkdir -p /var/lib/sandbox-bank && chown 10002:10002 /var/lib/sandbox-bank
USER 10002:10002
WORKDIR /repo/sandbox/bank
EXPOSE 8190 8191
HEALTHCHECK --interval=5s --timeout=3s --retries=30 CMD wget -qO- http://127.0.0.1:8190/healthz >/dev/null || exit 1
CMD ["node", "--disable-warning=ExperimentalWarning", "src/server.mjs"]
