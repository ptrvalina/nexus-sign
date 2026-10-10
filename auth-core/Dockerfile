# syntax=docker/dockerfile:1

# Build stage: compiles TypeScript and the native PKCS#11 binding (pkcs11js),
# which needs a C++ toolchain. The toolchain never reaches the runtime image.
FROM node:25-alpine AS build
RUN apk add --no-cache python3 make g++
WORKDIR /app
# A reviewed lockfile is required: the build installs exactly what it pins and
# fails without it (never resolves versions at build time).
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY tsconfig.json ./
COPY src ./src
RUN npm run build && npm prune --omit=dev

FROM node:25-alpine AS runtime
ENV NODE_ENV=production
# HSM calls run on libuv worker threads, shared with DNS, file and scrypt
# work; keep more threads than HSM_SESSION_POOL_SIZE.
ENV UV_THREADPOOL_SIZE=16
WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./
COPY public ./public
COPY src/db/schema.sql ./src/db/schema.sql
COPY migrations ./migrations
# The service runs with node only. The package managers bundled with the base
# image are not needed at runtime and are removed so they are not shipped.
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack \
      /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack \
      /usr/local/bin/yarn /usr/local/bin/yarnpkg /opt/yarn-*

RUN addgroup -S nexus && adduser -S nexus -G nexus
USER nexus

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD wget -qO- http://127.0.0.1:8080/healthz >/dev/null || exit 1
CMD ["node", "dist/server.js"]
