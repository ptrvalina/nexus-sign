import { z } from 'zod';
/** An optional setting where an empty value (`APNS_TEAM_ID=` in an env file) means unset. */
const optional = <T extends z.ZodTypeAny>(schema: T) => z.preprocess((v) => (v === '' ? undefined : v), schema.optional());

/**
 * All configuration the service needs, validated once at startup, so a
 * missing or malformed variable stops the process with a readable error.
 */
const envSchema = z.object({
  /** Deployment mode, with no default: a missing value must not silently
   * select development, which skips the production posture checks. */
  NODE_ENV: z.enum(['development', 'test', 'production'], {
    required_error: 'NODE_ENV is required: development, test or production',
  }),
  /** Outside production, running with the software HSM, without attestation
   * or without the mTLS gateway check needs this explicit opt-in, so a
   * mislabelled deployment does not quietly run without these controls.
   * Refused in production. */
  ALLOW_INSECURE_DEVELOPMENT: z.string().optional().transform((v) => v === 'true'),
  PORT: z.coerce.number().int().positive().default(8080),

  DATABASE_URL: z.string().min(1, 'DATABASE_URL is required'),
  DATABASE_POOL_MAX: z.coerce.number().int().positive().default(10),
  DATABASE_SSL: z.string().optional().transform((v) => v === 'true'),
  DATABASE_STATEMENT_TIMEOUT_MS: z.coerce.number().int().positive().default(5000),

  REDIS_URL: z.string().min(1, 'REDIS_URL is required'),
  REDIS_TLS_REQUIRED: z.string().optional().transform((v) => v === 'true'),

  /** 32 raw bytes, base64-encoded (see src/crypto/secretBox.ts). Required only
   * if a registered bank client has a webhook configured; generate with
   * `openssl rand -base64 32`. */
  WEBHOOK_SECRET_ENCRYPTION_KEY: z.string().optional(),
  /** Encrypts per-credential offline confirmation keys (32 bytes, base64).
   * Required when OFFLINE_CONFIRMATION_ENABLED is true. */
  DEVICE_SECRET_ENCRYPTION_KEY: z.string().optional(),
  /** Where the master keys come from. `env` (default): the base64
   * keys above. `hsm` (required in production): only wrapped keys are
   * configured (`<NAME>_WRAPPED`, `<NAME>_PREVIOUS_WRAPPED`), made with the
   * HSM key-encryption key PKCS11_KEK_LABEL and unwrapped in the HSM at
   * startup (src/crypto/masterKeyVault.ts, cli/masterKeys.js). */
  MASTER_KEY_SOURCE: z.enum(['env', 'hsm']).default('env'),
  PKCS11_KEK_LABEL: z.string().optional(),
  WEBHOOK_SECRET_ENCRYPTION_KEY_WRAPPED: z.string().optional(),
  DEVICE_SECRET_ENCRYPTION_KEY_WRAPPED: z.string().optional(),
  ADMIN_SECRET_ENCRYPTION_KEY_WRAPPED: z.string().optional(),
  WEBHOOK_SECRET_ENCRYPTION_KEY_PREVIOUS_WRAPPED: z.string().optional(),
  DEVICE_SECRET_ENCRYPTION_KEY_PREVIOUS_WRAPPED: z.string().optional(),
  ADMIN_SECRET_ENCRYPTION_KEY_PREVIOUS_WRAPPED: z.string().optional(),
  /** Key rotation: previous master keys, comma-separated base64,
   * accepted for decryption only until cli/rotateSecretKeys.js has
   * re-encrypted the stored secrets under the current key. */
  WEBHOOK_SECRET_ENCRYPTION_KEY_PREVIOUS: z.string().optional(),
  DEVICE_SECRET_ENCRYPTION_KEY_PREVIOUS: z.string().optional(),
  ADMIN_SECRET_ENCRYPTION_KEY_PREVIOUS: z.string().optional(),

  /** How long an OAuth2 client-credentials access token stays valid. */
  OAUTH_TOKEN_TTL_SECONDS: z.coerce.number().int().min(60).max(86_400).default(3600),
  REQUIRE_IDEMPOTENCY_KEY: z.string().optional().transform((v) => v !== 'false'),

  /** Production API gateway/mTLS controls. The Auth Core itself may terminate TLS elsewhere;
   * when true, only requests arriving from configured trusted proxy IPs and carrying the
   * gateway's verified-client-certificate marker are accepted on protected routes. */
  REQUIRE_MTLS_HEADER: z.string().optional().transform((v) => v === 'true'),
  MTLS_VERIFIED_HEADER: z.string().default('x-client-cert-verified'),
  /** Header in which the gateway forwards the SHA-256 fingerprint (hex) of
   * the verified client certificate; bank tokens are bound to the
   * fingerprints registered for the client. The gateway must overwrite any
   * inbound value of this header and of MTLS_VERIFIED_HEADER. */
  MTLS_CERT_SHA256_HEADER: z.string().default('x-client-cert-sha256'),
  TRUSTED_PROXY_IPS: z.string().optional().transform((v) => (v ?? '').split(',').map((x) => x.trim()).filter(Boolean)),

  /** Webhook SSRF/egress controls. In production prefer an explicit host allow-list. */
  WEBHOOK_ALLOWED_HOSTS: z.string().optional().transform((v) => (v ?? '').split(',').map((x) => x.trim().toLowerCase()).filter(Boolean)),
  WEBHOOK_REQUIRE_HTTPS: z.string().optional().transform((v) => v !== 'false'),


  /** Enrolled devices sign each request with their hardware authentication
   * key; this is the accepted difference between the device timestamp and
   * server time. The nonce of each request is remembered for twice as long. */
  DEVICE_REQUEST_MAX_SKEW_SECONDS: z.coerce.number().int().min(30).max(900).default(300),
  /** How long after the customer's confirmation the bank may request the
   * commit of a transaction. */
  BANK_COMMIT_MAX_AGE_SECONDS: z.coerce.number().int().min(60).max(7 * 24 * 3600).default(3600),
  /** How often PENDING_USER authorizations past their expiry are moved to
   * EXPIRED (and the bank's webhook is notified). Read paths report EXPIRED
   * immediately regardless of this interval. */
  AUTHORIZATION_EXPIRY_SWEEP_MS: z.coerce.number().int().min(500).max(300_000).default(10_000),
  // --- In-app audio/video calls (ADR 0017) ---
  /** STUN servers for the device and the operator console, e.g.
   * `stun:turn.bank.example:3478` (comma-separated). */
  WEBRTC_STUN_URLS: z.string().optional().transform((v) => (v ?? '').split(',').map((x) => x.trim()).filter(Boolean)),
  /** TURN servers of the bank (coturn with `use-auth-secret`), e.g.
   * `turns:turn.bank.example:5349?transport=tcp` (comma-separated). */
  WEBRTC_TURN_URLS: z.string().optional().transform((v) => (v ?? '').split(',').map((x) => x.trim()).filter(Boolean)),
  /** The coturn `static-auth-secret`; Auth Core derives per-session TURN
   * credentials from it (TURN REST convention). */
  WEBRTC_TURN_SECRET: optional(z.string().min(16)),
  WEBRTC_TURN_CREDENTIAL_TTL_SECONDS: z.coerce.number().int().min(60).max(3600).default(600),

  /** How long a shutdown waits for requests in flight before closing them. */
  SHUTDOWN_DRAIN_MS: z.coerce.number().int().min(0).max(120_000).default(15_000),

  /** Path prefix the gateway removes before forwarding (e.g. `/nexus-sign`
   * when the SDK base URL is https://api.bank.example/nexus-sign). Devices
   * sign the path they send, so it is added back before verification. */
  DEVICE_REQUEST_PATH_PREFIX: z.string().regex(/^(\/[A-Za-z0-9._~-]+)*$/).default(''),

  /** Offline confirmation: the customer confirms a transaction shown as a QR
   * code without network on the phone and types an 8-digit code. */
  OFFLINE_CONFIRMATION_ENABLED: z.string().optional().transform((v) => v === 'true'),
  /** Bearer token required for GET /metrics. Without it the endpoint
   * is open to every caller that passes the gateway check (any bank system).
   * Required in production; at least 32 characters. */
  METRICS_BEARER_TOKEN: z.string().optional(),
  /** Where used device request nonces are remembered. `postgres`
   * (default): table device_request_nonces, as durable as the rest of the
   * data. `redis`: as before 2.0.0; a failover to an asynchronous replica or a
   * restore can forget nonces. Production requires postgres. */
  DEVICE_NONCE_STORE: z.enum(['postgres', 'redis']).default('postgres'),
  /** Highest amount, per currency, that may be confirmed with an
   * offline code, e.g. `PLN:100000,EUR:20000` (minor units). The offline code
   * is an HMAC under a key Auth Core also holds, so whoever has the database
   * and DEVICE_SECRET_ENCRYPTION_KEY can compute it; the cap bounds what such
   * a code can authorize. Set in the deployment, not in the database.
   * Currencies not listed are not offered offline. Required in production
   * when OFFLINE_CONFIRMATION_ENABLED is true. */
  OFFLINE_CONFIRMATION_MAX_AMOUNT: z.string().optional(),
  /** Most offline confirmations one credential may make in 24 hours.
   * Bounds how many authorizations a computed (forged) code could confirm
   * before the bank notices. Unset: no limit; required in production when
   * offline confirmation is enabled. */
  OFFLINE_CONFIRMATION_MAX_PER_CREDENTIAL_PER_DAY: z.coerce.number().int().min(1).max(1000).optional(),
  /** offline confirmation protocol (docs/protocol/offline-confirmation-v2-deferred-signature.md).
   * `deferred_signature` (default, v2): QR prefix NXS2.; an accepted code
   * leaves the authorization OFFLINE_PROVISIONAL until the device uploads its
   * ECDSA signature over the same bytes; only then VERIFIED. `immediate` (v1,
   * as up to 2.0.0-rc.2): QR prefix NXS1.; an accepted code is VERIFIED at
   * once. Production requires deferred_signature. */
  OFFLINE_CONFIRMATION_MODE: z.enum(['deferred_signature', 'immediate']).default('deferred_signature'),
  /** v2: hours after an accepted code within which the device signature must
   * arrive; afterwards the authorization becomes OFFLINE_UNSIGNED (final). */
  OFFLINE_SIGNATURE_DEADLINE_HOURS: z.coerce.number().int().min(1).max(720).default(72),

  // --- Secure push (docs/protocol/secure-push.md) ---

  /** Delivers push messages through APNs and FCM: authorization requests for
   * bank clients in push mode NEXUS, and messages the bank sends with
   * POST /v1/push-messages. Requires DEVICE_SECRET_ENCRYPTION_KEY, which also
   * encrypts the per-device push keys, and at least one provider below. */
  PUSH_DELIVERY_ENABLED: z.string().optional().transform((v) => v === 'true'),

  /** APNs token authentication: the Team ID, the key ID and the .p8 key
   * (PEM text, not a path) of an APNs auth key, and the bank app's bundle ID. */
  APNS_TEAM_ID: optional(z.string().regex(/^[A-Z0-9]{10}$/)),
  APNS_KEY_ID: optional(z.string().regex(/^[A-Z0-9]{10}$/)),
  APNS_PRIVATE_KEY_PEM: optional(z.string()),
  APNS_TOPIC: optional(z.string().regex(/^[A-Za-z0-9.-]{1,155}$/)),

  /** FCM HTTP v1: the Firebase project of the bank's Android app and a service
   * account allowed to send to it (JSON key contents). FCM only carries the
   * sealed envelope; no Firebase SDK is part of NEXUS-SIGN. */
  FCM_PROJECT_ID: optional(z.string().regex(/^[a-z][a-z0-9-]{4,62}$/)),
  FCM_SERVICE_ACCOUNT_JSON: optional(z.string()),

  /** How long an undelivered message is retried and kept by APNs and FCM. */
  PUSH_MESSAGE_TTL_SECONDS: z.coerce.number().int().min(60).max(2_419_200).default(86_400),

  /** Visible text of the APNs alert before the app's notification service
   * extension replaces it with the decrypted message. Not sent to FCM:
   * Android messages are data-only and shown by the app. */
  PUSH_ALERT_TITLE: z.string().min(1).max(64).default('New message'),
  PUSH_ALERT_BODY: z.string().max(120).default(''),

  /** Text of the authorization request push when the bank gives none. The
   * amount and payee the customer approves always come from the signed bytes. */
  PUSH_AUTHORIZATION_TITLE: z.string().min(1).max(120).default('Confirm payment'),
  PUSH_AUTHORIZATION_BODY: z.string().max(600).default('Open the app to review and confirm.'),

  /** Security notice sent to a device that was replaced by another one. */
  PUSH_REPLACEMENT_TITLE: z.preprocess((v) => (v === '' ? undefined : v), z.string().min(1).max(120).default('Your account was set up on a new device')),
  PUSH_REPLACEMENT_BODY: z.preprocess((v) => (v === '' ? undefined : v), z.string().max(600).default('If this was not you, contact your bank immediately.')),

  // --- Server-side cryptographic boundary ---
  HSM_ADAPTER: z.enum(['software', 'pkcs11']).default('software'),
  PKCS11_MODULE_PATH: z.string().optional(),
  PKCS11_SLOT_INDEX: z.coerce.number().int().nonnegative().default(0),
  PKCS11_PIN: z.string().optional(),
  PKCS11_EVIDENCE_KEY_LABEL: z.string().optional(),
  PKCS11_EVIDENCE_KEY_VERSION: z.coerce.number().int().positive().default(1),
  /** Token (CKA_LABEL of the token) holding the evidence key. Required in
   * production; PKCS11_SLOT_INDEX is only a development fallback. */
  PKCS11_TOKEN_LABEL: optional(z.string().min(1).max(32)),
  /** CKA_ID (hex) of the evidence key, required when the label is not unique. */
  PKCS11_EVIDENCE_KEY_ID: optional(z.string().regex(/^([0-9a-fA-F]{2})+$/)),
  /** Public keys (PEM, concatenated) of evidence keys retired by rotation.
   * Records keep naming the key that sealed them (sealKeyId), so these stay
   * published and accepted for verification. */
  EVIDENCE_RETIRED_PUBLIC_KEYS_PEM: optional(z.string()),
  /** Logged-in PKCS#11 sessions used in parallel. */
  HSM_SESSION_POOL_SIZE: z.coerce.number().int().min(1).max(64).default(4),
  /** Deadline for one HSM operation (and for waiting for a free session). */
  HSM_OPERATION_TIMEOUT_MS: z.coerce.number().int().min(100).max(60_000).default(5000),

  // --- Device attestation verification ---

  /** When true, device enrolment and recovery are refused unless App Attest
   * or Play Integrity verification succeeds. Mandatory in production. */
  REQUIRE_VALID_ATTESTATION: z.string().optional().transform((v) => v === 'true'),

  /** Google Cloud service account for the Play Integrity decode API: the
   * JSON key file's contents, not a path, so it can be injected as a secret.
   * Without it, Android attestation cannot be verified (and is rejected when
   * REQUIRE_VALID_ATTESTATION is true). */
  GOOGLE_SERVICE_ACCOUNT_JSON: z.string().optional(),

  /** The Android package name Play Integrity tokens are expected to
   * have been issued for. Required if GOOGLE_SERVICE_ACCOUNT_JSON is
   * set. */
  ANDROID_PACKAGE_NAME: z.string().optional(),

  /** Apple App Attest App ID (TEAMID.BUNDLEID) that attestations are
   * expected to have been generated for. Without it, iOS attestation cannot
   * be verified. */
  APPLE_APP_ID: z.string().optional(),

  /** Apple App Attest root CA PEM. Required (pinned) in production; outside
   * production it is fetched on first use from
   * https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem
   * and cached (see src/crypto/appleRootCert.ts). */
  APPLE_APP_ATTEST_ROOT_CA_PEM: z.string().optional(),

  ANDROID_REQUIRED_DEVICE_VERDICT: z.enum(['MEETS_BASIC_INTEGRITY', 'MEETS_DEVICE_INTEGRITY', 'MEETS_STRONG_INTEGRITY']).default('MEETS_DEVICE_INTEGRITY'),

  /** Where Android keys must live, proven by Keystore key attestation
   * (androidKeyAttestation.ts): REQUIRE_STRONGBOX (StrongBox only),
   * REQUIRE_HARDWARE_BACKED (TEE or StrongBox; default), ALLOW_TEE (the same
   * acceptance as REQUIRE_HARDWARE_BACKED, named for policies written as "TEE
   * allowed"), ALLOW_SOFTWARE (development only; a production blocker). A key
   * that does not meet the policy is refused; nothing falls back silently. */
  ANDROID_KEY_SECURITY_POLICY: z.enum(['REQUIRE_STRONGBOX', 'REQUIRE_HARDWARE_BACKED', 'ALLOW_TEE', 'ALLOW_SOFTWARE']).default('REQUIRE_HARDWARE_BACKED'),
  /** Refuse devices whose bootloader is unlocked or whose boot is not verified. */
  ANDROID_REQUIRE_LOCKED_BOOTLOADER: z.string().optional().transform((v) => v !== 'false'),
  /** SHA-256 (hex, comma-separated) of the bank app's signing certificates;
   * checked in key attestation and Play Integrity verdicts. */
  ANDROID_APP_CERT_SHA256: z.string().optional().transform((v) => (v ?? '').split(',').map((x) => x.trim().toLowerCase().replace(/:/g, '')).filter(Boolean)),
  /** Google's attestation status list (https://android.googleapis.com/attestation/status),
   * downloaded and refreshed by operations; revoked attestation keys are refused. */
  ANDROID_ATTESTATION_STATUS_FILE: optional(z.string()),
  ATTESTATION_MAX_AGE_SECONDS: z.coerce.number().int().min(30).max(3600).default(300),

  /** Whether the admin dashboard's session cookie gets the `Secure` flag.
   * Defaults to true; set to 'false' only for local development over plain HTTP. */
  ADMIN_COOKIE_SECURE: z
    .string()
    .optional()
    .transform((v) => v !== 'false'),

  /** Admin logins need a TOTP code. On by default; 'false' only for local
   * development (accounts that have a TOTP secret still need a code). */
  ADMIN_MFA_REQUIRED: z.string().optional().transform((v) => v !== 'false'),
  /** 32 random bytes, base64: encrypts admin TOTP secrets (secretBox.ts). */
  ADMIN_SECRET_ENCRYPTION_KEY: optional(z.string()),
  /** How long a revocation or reactivation request waits for a second admin. */
  ADMIN_APPROVAL_TTL_HOURS: z.coerce.number().int().min(1).max(168).default(24),

});

export type Env = z.infer<typeof envSchema>;

function loadEnv(): Env {
  const parsed = envSchema.safeParse(process.env);
  if (!parsed.success) {
    const issues = parsed.error.issues
      .map((issue) => `  - ${issue.path.join('.')}: ${issue.message}`)
      .join('\n');
    throw new Error(`Invalid environment configuration:\n${issues}`);
  }
  return parsed.data;
}

export const env = loadEnv();
