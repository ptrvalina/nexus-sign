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
  if (!config.WEBHOOK_SECRET_ENCRYPTION_KEY) blockers.push('WEBHOOK_SECRET_ENCRYPTION_KEY is required in production');
  if (!config.ADMIN_COOKIE_SECURE) {
    blockers.push('ADMIN_COOKIE_SECURE must be true in production');
  }
  if (!config.ADMIN_MFA_REQUIRED) blockers.push('ADMIN_MFA_REQUIRED must be true in production');
  if (!config.ADMIN_SECRET_ENCRYPTION_KEY) blockers.push('ADMIN_SECRET_ENCRYPTION_KEY is required in production (admin TOTP secrets)');
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
  // Master keys are checked at startup, not at first use (NXS-038).
  for (const name of ['WEBHOOK_SECRET_ENCRYPTION_KEY', 'DEVICE_SECRET_ENCRYPTION_KEY', 'ADMIN_SECRET_ENCRYPTION_KEY'] as const) {
    const value = config[name];
    if (value !== undefined && value !== '' && (!/^[A-Za-z0-9+/]+={0,2}$/.test(value) || Buffer.from(value, 'base64').length !== 32)) {
      errors.push(`${name} must be 32 random bytes, base64-encoded`);
    }
  }
  if (config.OFFLINE_CONFIRMATION_ENABLED && !config.DEVICE_SECRET_ENCRYPTION_KEY) {
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
    if (!config.DEVICE_SECRET_ENCRYPTION_KEY) errors.push('DEVICE_SECRET_ENCRYPTION_KEY is required when PUSH_DELIVERY_ENABLED is true');
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
  return settings;
}
