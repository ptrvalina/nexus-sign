import { env } from '../config/env';

const APPLE_ROOT_CA_URL = 'https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem';

let cachedPem: string | null = null;

/**
 * Returns Apple's App Attest root CA certificate, PEM-encoded.
 *
 * Production deployments pin the root with APPLE_APP_ATTEST_ROOT_CA_PEM
 * (see env.ts). Without it, the certificate is fetched once from Apple's
 * published URL and cached for the life of the process.
 */
export async function getAppleAppAttestRootCertPem(): Promise<string> {
  if (env.APPLE_APP_ATTEST_ROOT_CA_PEM) {
    return env.APPLE_APP_ATTEST_ROOT_CA_PEM;
  }
  if (cachedPem) {
    return cachedPem;
  }

  const response = await fetch(APPLE_ROOT_CA_URL, { signal: AbortSignal.timeout(10_000) });
  if (!response.ok) {
    throw new Error(`Failed to fetch Apple App Attest root CA: HTTP ${response.status}`);
  }

  const arrayBuffer = await response.arrayBuffer();
  const bytes = Buffer.from(arrayBuffer);

  // The file behind the ".pem" URL has been served as DER; accept both.
  const pem = looksLikePem(bytes) ? bytes.toString('utf8') : derToPem(bytes);

  cachedPem = pem;
  return pem;
}

function looksLikePem(bytes: Buffer): boolean {
  return bytes.subarray(0, 27).toString('utf8') === '-----BEGIN CERTIFICATE-----';
}

function derToPem(der: Buffer): string {
  const base64 = der.toString('base64');
  const wrapped = base64.match(/.{1,64}/g)?.join('\n') ?? base64;
  return `-----BEGIN CERTIFICATE-----\n${wrapped}\n-----END CERTIFICATE-----\n`;
}
