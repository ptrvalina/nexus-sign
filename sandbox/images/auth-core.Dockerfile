# syntax=docker/dockerfile:1
# Auth Core for the sandbox, built from the unchanged auth-core/ sources of
# this checkout (no patch is applied), plus SoftHSM 2.7.0 as the sandbox's
# test HSM. The product image (auth-core/Dockerfile) is not used here because
# it carries no PKCS#11 module; it is not modified either.
# Build context: the repository root (see sandbox/compose.yaml).

# SoftHSM 2.7.0, pinned to the tag's commit as in CI. Ubuntu and Alpine package
# older releases without CKM_ECDSA_SHA256, which Auth Core seals evidence with.
FROM node:22-alpine AS softhsm
ARG SOFTHSM_COMMIT=13e6e86b83748fef74046dbf0c91f664b7acc1c3
RUN apk add --no-cache git autoconf automake libtool pkgconf openssl-dev g++ make
RUN git clone -q --depth 1 --branch 2.7.0 https://github.com/softhsm/SoftHSMv2 /src \
 && cd /src && test "$(git rev-parse HEAD)" = "$SOFTHSM_COMMIT" \
 && sh autogen.sh && ./configure --prefix=/opt/softhsm --with-crypto-backend=openssl --disable-gost \
 && make -j"$(nproc)" && make install

# Auth Core exactly as auth-core/Dockerfile builds it: the reviewed lockfile, then tsc.
FROM node:22-alpine AS build
RUN apk add --no-cache python3 make g++
WORKDIR /app
COPY auth-core/package.json auth-core/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY auth-core/tsconfig.json ./
COPY auth-core/src ./src
RUN npm run build && npm prune --omit=dev

FROM node:22-alpine
RUN apk add --no-cache libstdc++ libcrypto3
COPY --from=softhsm /opt/softhsm /opt/softhsm
WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY auth-core/package.json ./
COPY auth-core/public ./public
COPY auth-core/src/db/schema.sql ./src/db/schema.sql
COPY auth-core/migrations ./migrations
COPY sandbox/stack/auth-core-entrypoint.sh sandbox/stack/hsm-init.cjs /sandbox/
RUN addgroup -S -g 10001 nexus && adduser -S -u 10001 -G nexus nexus \
 && mkdir -p /var/lib/sandbox-hsm /run/sandbox-credentials && chown 10001:10001 /var/lib/sandbox-hsm /run/sandbox-credentials
USER 10001:10001
ENV UV_THREADPOOL_SIZE=16 SOFTHSM2_CONF=/var/lib/sandbox-hsm/softhsm2.conf
EXPOSE 8080
HEALTHCHECK --interval=5s --timeout=3s --retries=60 CMD wget -qO- http://127.0.0.1:8080/readyz >/dev/null || exit 1
ENTRYPOINT ["/bin/sh", "/sandbox/auth-core-entrypoint.sh"]
