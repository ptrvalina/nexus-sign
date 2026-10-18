import type { Env } from './env';

/**
 * Settings that must hold before Auth Core serves production traffic. Startup
 * refuses to continue while any of them is missing (see server.ts).
 */
export function productionBlockers(config: Env): string[] {
  if (config.NODE_ENV !== 'production') return [];

  const blockers: string[] = [];

  if (config.ALLOW_INSECURE_DEVELOPMENT) blockers.push('ALLOW_INSECURE_DEVELOPMENT must not be set in production');

  if (config.HSM_ADAPTER !== 'pkcs11') {
    blockers.push('HSM_ADAPTER must be pkcs11 in production');
  }
  if (!config.REQUIRE_VALID_ATTESTATION) {
    blockers.push('REQUIRE_VALID_ATTESTATION must be true in production');
  }
  const iosAttestation = Boolean(config.APPLE_APP_ID && config.APPLE_APP_ATTEST_ROOT_CA_PEM);
  const androidAttestation = Boolean(config.GOOGLE_SERVICE_ACCOUNT_JSON && config.ANDROID_PACKAGE_NAME);
  if (!iosAttestation && !androidAttestation) {
    blockers.push('attestation must be configured for at least one platform: APPLE_APP_ID + APPLE_APP_ATTEST_ROOT_CA_PEM, and/or GOOGLE_SERVICE_ACCOUNT_JSON + ANDROID_PACKAGE_NAME');
  }
  if (config.APPLE_APP_ID && !config.APPLE_APP_ATTEST_ROOT_CA_PEM) blockers.push('APPLE_APP_ATTEST_ROOT_CA_PEM must be pinned in production');
  if (androidAttestation) {
    if (config.ANDROID_KEY_SECURITY_POLICY === 'ALLOW_SOFTWARE') blockers.push('ANDROID_KEY_SECURITY_POLICY=ALLOW_SOFTWARE is not allowed in production');
    if (!config.ANDROID_ATTESTATION_STATUS_FILE) blockers.push('ANDROID_ATTESTATION_STATUS_FILE (Google attestation status list) is required in production');
    if (config.ANDROID_APP_CERT_SHA256.length === 0) blockers.push('ANDROID_APP_CERT_SHA256 (the app signing certificate digests) is required in production');
    if (!config.ANDROID_REQUIRE_LOCKED_BOOTLOADER) blockers.push('ANDROID_REQUIRE_LOCKED_BOOTLOADER must be true in production');
    if (config.ANDROID_REQUIRED_DEVICE_VERDICT === 'MEETS_BASIC_INTEGRITY') blockers.push('ANDROID_REQUIRED_DEVICE_VERDICT must be MEETS_DEVICE_INTEGRITY or MEETS_STRONG_INTEGRITY in production');
  }
  if (!masterKeyConfigured(config, 'WEBHOOK_SECRET_ENCRYPTION_KEY')) blockers.push('WEBHOOK_SECRET_ENCRYPTION_KEY is required in production');
  if (config.MASTER_KEY_SOURCE !== 'hsm') blockers.push('MASTER_KEY_SOURCE must be hsm in production (FI-005: master keys wrapped by the HSM, not plaintext in the environment)');
  if (!config.ADMIN_COOKIE_SECURE) {
    blockers.push('ADMIN_COOKIE_SECURE must be true in production');
  }
  if (!config.ADMIN_MFA_REQUIRED) blockers.push('ADMIN_MFA_REQUIRED must be true in production');
  if (!masterKeyConfigured(config, 'ADMIN_SECRET_ENCRYPTION_KEY')) blockers.push('ADMIN_SECRET_ENCRYPTION_KEY is required in production (admin TOTP secrets)');
  if (!config.METRICS_BEARER_TOKEN || config.METRICS_BEARER_TOKEN.length < 32) blockers.push('METRICS_BEARER_TOKEN of at least 32 characters is required in production (FI-030)');
  if (config.DEVICE_NONCE_STORE === 'redis') blockers.push('DEVICE_NONCE_STORE must be postgres in production (FI-008: Redis failover can forget used nonces)');
  if (config.OFFLINE_CONFIRMATION_ENABLED && config.OFFLINE_CONFIRMATION_MAX_PER_CREDENTIAL_PER_DAY === undefined) {
    blockers.push('OFFLINE_CONFIRMATION_MAX_PER_CREDENTIAL_PER_DAY is required in production when OFFLINE_CONFIRMATION_ENABLED is true (FI-004)');
  }
  if (config.OFFLINE_CONFIRMATION_ENABLED && config.OFFLINE_CONFIRMATION_MODE !== 'deferred_signature') {
    blockers.push('OFFLINE_CONFIRMATION_MODE must be deferred_signature in production when OFFLINE_CONFIRMATION_ENABLED is true (FI-004: a code alone can be computed by whoever controls Auth Core)');
  }
  if (config.OFFLINE_CONFIRMATION_ENABLED && !config.OFFLINE_CONFIRMATION_MAX_AMOUNT?.trim()) {
    blockers.push('OFFLINE_CONFIRMATION_MAX_AMOUNT is required in production when OFFLINE_CONFIRMATION_ENABLED is true (FI-004: offline codes can be computed by whoever holds the database and DEVICE_SECRET_ENCRYPTION_KEY)');
  }
  if (!config.PKCS11_MODULE_PATH || !config.PKCS11_PIN) {
    blockers.push('PKCS11_MODULE_PATH and PKCS11_PIN are required in production');
  }
  if (!config.PKCS11_TOKEN_LABEL) blockers.push('PKCS11_TOKEN_LABEL is required in production (slot numbers can change)');
  if (!config.PKCS11_EVIDENCE_KEY_LABEL) {
    blockers.push('PKCS11_EVIDENCE_KEY_LABEL is required for HSM evidence sealing in production');
  }
  if (!config.DATABASE_SSL) blockers.push('DATABASE_SSL must be true in production');
  if (!config.REDIS_TLS_REQUIRED) blockers.push('REDIS_TLS_REQUIRED must be true in production');
  if (!config.REQUIRE_MTLS_HEADER) blockers.push('REQUIRE_MTLS_HEADER must be true in production');
  if (config.TRUSTED_PROXY_IPS.length === 0) blockers.push('TRUSTED_PROXY_IPS must list the mTLS gateway addresses in production');
  if (config.WEBHOOK_ALLOWED_HOSTS.length === 0) blockers.push('WEBHOOK_ALLOWED_HOSTS must be configured in production');
  if (!config.WEBHOOK_REQUIRE_HTTPS) blockers.push('WEBHOOK_REQUIRE_HTTPS must be true in production');
  if (!config.REDIS_URL.startsWith('rediss://')) blockers.push('REDIS_URL must use rediss:// in production');

  return blockers;
}

/** Settings that are inconsistent in any environment. */
export function configurationErrors(config: Env): string[] {
  const errors: string[] = [];
  if (config.NODE_ENV !== 'production' && !config.ALLOW_INSECURE_DEVELOPMENT) {
    for (const setting of insecureDevelopmentSettings(config)) {
      errors.push(`${setting} is a development setting: set ALLOW_INSECURE_DEVELOPMENT=true to run with it outside production`);
    }
  }
  if (config.MASTER_KEY_SOURCE === 'hsm') {
    if (!config.PKCS11_MODULE_PATH || !config.PKCS11_PIN || !config.PKCS11_KEK_LABEL) errors.push('MASTER_KEY_SOURCE=hsm needs PKCS11_MODULE_PATH, PKCS11_PIN and PKCS11_KEK_LABEL');
    for (const name of MASTER_KEY_ENV_NAMES) {
      const c = config as Record<string, unknown>;
      if (c[name] || c[`${name}_PREVIOUS`]) errors.push(`${name} must not be set in plaintext with MASTER_KEY_SOURCE=hsm; configure ${name}_WRAPPED`);
      if (c[`${name}_PREVIOUS_WRAPPED`] && !c[`${name}_WRAPPED`]) errors.push(`${name}_PREVIOUS_WRAPPED is set but ${name}_WRAPPED is not`);
    }
  } else {
    for (const name of MASTER_KEY_ENV_NAMES) {
      const c = config as Record<string, unknown>;
      if (c[`${name}_WRAPPED`] || c[`${name}_PREVIOUS_WRAPPED`]) errors.push(`${name}_WRAPPED is only read with MASTER_KEY_SOURCE=hsm`);
    }
  }
  // Master keys are checked at startup, not at first use (NXS-038).
  for (const name of ['WEBHOOK_SECRET_ENCRYPTION_KEY', 'DEVICE_SECRET_ENCRYPTION_KEY', 'ADMIN_SECRET_ENCRYPTION_KEY'] as const) {
    const value = config[name];
    if (value !== undefined && value !== '' && (!/^[A-Za-z0-9+/]+={0,2}$/.test(value) || Buffer.from(value, 'base64').length !== 32)) {
      errors.push(`${name} must be 32 random bytes, base64-encoded`);
    }
    const previous = (config as Record<string, unknown>)[`${name}_PREVIOUS`];
    if (typeof previous === 'string' && previous.trim() !== '') {
      if (!value) errors.push(`${name}_PREVIOUS is set but ${name} is not`);
      for (const entry of previous.split(',')) {
        const trimmed = entry.trim();
        if (!/^[A-Za-z0-9+/]+={0,2}$/.test(trimmed) || Buffer.from(trimmed, 'base64').length !== 32) {
          errors.push(`${name}_PREVIOUS must list 32-byte keys, base64-encoded, separated by commas`);
        } else if (value && Buffer.from(trimmed, 'base64').equals(Buffer.from(value, 'base64'))) {
          errors.push(`${name}_PREVIOUS must not repeat the current ${name}`);
        }
      }
    }
  }
  if (config.OFFLINE_CONFIRMATION_MAX_AMOUNT !== undefined && config.OFFLINE_CONFIRMATION_MAX_AMOUNT.trim() !== '') {
    try { parseOfflineLimits(config.OFFLINE_CONFIRMATION_MAX_AMOUNT); } catch (error) { errors.push(error instanceof Error ? error.message : String(error)); }
  }
  if (config.OFFLINE_CONFIRMATION_ENABLED && !masterKeyConfigured(config, 'DEVICE_SECRET_ENCRYPTION_KEY')) {
    errors.push('DEVICE_SECRET_ENCRYPTION_KEY is required when OFFLINE_CONFIRMATION_ENABLED is true');
  }

  const apns = [config.APNS_TEAM_ID, config.APNS_KEY_ID, config.APNS_PRIVATE_KEY_PEM, config.APNS_TOPIC];
  const fcm = [config.FCM_PROJECT_ID, config.FCM_SERVICE_ACCOUNT_JSON];
  if (apns.some(Boolean) && !apns.every(Boolean)) {
    errors.push('APNS_TEAM_ID, APNS_KEY_ID, APNS_PRIVATE_KEY_PEM and APNS_TOPIC must be set together');
  }
  if (fcm.some(Boolean) && !fcm.every(Boolean)) {
    errors.push('FCM_PROJECT_ID and FCM_SERVICE_ACCOUNT_JSON must be set together');
  }
  if (config.PUSH_DELIVERY_ENABLED) {
    if (!masterKeyConfigured(config, 'DEVICE_SECRET_ENCRYPTION_KEY')) errors.push('DEVICE_SECRET_ENCRYPTION_KEY is required when PUSH_DELIVERY_ENABLED is true');
    if (!apns.every(Boolean) && !fcm.every(Boolean)) {
      errors.push('PUSH_DELIVERY_ENABLED needs APNs (APNS_*) and/or FCM (FCM_*) to be configured');
    }
  }
  return errors;
}

/** Settings that switch off a production control; allowed outside production
 * only with ALLOW_INSECURE_DEVELOPMENT=true. */
export function insecureDevelopmentSettings(config: Env): string[] {
  const settings: string[] = [];
  if (config.HSM_ADAPTER === 'software') settings.push('HSM_ADAPTER=software');
  if (!config.REQUIRE_VALID_ATTESTATION) settings.push('REQUIRE_VALID_ATTESTATION=false');
  if (!config.REQUIRE_MTLS_HEADER) settings.push('REQUIRE_MTLS_HEADER=false');
  if (!config.ADMIN_MFA_REQUIRED) settings.push('ADMIN_MFA_REQUIRED=false');
  // FI-004: offline confirmation v1 accepts a code alone.
  if (config.OFFLINE_CONFIRMATION_ENABLED && config.OFFLINE_CONFIRMATION_MODE === 'immediate') settings.push('OFFLINE_CONFIRMATION_MODE=immediate');
  return settings;
}

/** `PLN:100000,EUR:20000` → Map(currency → max amount in minor units). */
export function parseOfflineLimits(value: string): Map<string, bigint> {
  const limits = new Map<string, bigint>();
  for (const entry of value.split(',').map((x) => x.trim()).filter(Boolean)) {
    const match = /^([A-Z]{3}):(0|[1-9][0-9]{0,29})$/.exec(entry);
    if (!match) throw new Error(`OFFLINE_CONFIRMATION_MAX_AMOUNT: "${entry}" is not CURRENCY:amountMinor (e.g. PLN:100000)`);
    if (limits.has(match[1])) throw new Error(`OFFLINE_CONFIRMATION_MAX_AMOUNT lists ${match[1]} twice`);
    limits.set(match[1], BigInt(match[2]));
  }
  return limits;
}

const MASTER_KEY_ENV_NAMES = ['WEBHOOK_SECRET_ENCRYPTION_KEY', 'DEVICE_SECRET_ENCRYPTION_KEY', 'ADMIN_SECRET_ENCRYPTION_KEY'] as const;

/** A master key is configured in plaintext (MASTER_KEY_SOURCE=env) or wrapped (hsm). */
export function masterKeyConfigured(config: Env, name: typeof MASTER_KEY_ENV_NAMES[number]): boolean {
  const c = config as Record<string, unknown>;
  return config.MASTER_KEY_SOURCE === 'hsm' ? Boolean(c[`${name}_WRAPPED`]) : Boolean(c[name]);
}
