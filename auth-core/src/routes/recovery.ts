import { Router } from 'express';
import { z } from 'zod';
import type { HsmAdapter } from '../crypto/hsmAdapter';
import { authenticateBankClient, type AuthenticatedRequest } from '../middleware/auth';
import { enrolmentAttestation, platformMatches, verifyDeviceAttestation } from '../services/attestationVerificationService';
import { env } from '../config/env';
import { completeRecovery, createRecoverySession, getRecoveryAttestationBinding } from '../services/recoveryService';
import { buildAttestationBinding } from '../services/attestationBinding';
import { UnauthorizedError } from '../services/errors';

/**
 * Account recovery (recovery protocol 2, recoveryService.ts). The recovery
 * phrase never leaves the device. The bank backend opens a recovery session
 * after re-identifying the customer; it receives the wrapped recovery key,
 * which only the phrase opens, and cannot complete the recovery itself.
 */
const sessionSchema = z.object({ bankCustomerRef: z.string().min(1).max(128) });
const completeSchema = z.object({
  /** DER ECDSA signature by the recovery key (recovery protocol 2). */
  proof: z.string().min(40).max(256),
  newPublicKeyPem: z.string().min(1).max(4096),
  platform: z.enum(['IOS', 'ANDROID', 'OTHER']),
  securityLevel: z.string().min(1).max(32),
  authPublicKeyPem: z.string().min(1).max(4096),
  offlinePublicKeyPem: z.string().min(1).max(4096).optional(),
  offlineKeyAgreement: z.enum(['STATIC', 'PER_AUTHORIZATION']).optional(),
  deviceAttestation: z.record(z.string(), z.unknown()).default({}),
});

export function buildRecoveryRouter(hsmAdapter: HsmAdapter): Router {
  const router = Router();

  /** Bank backend: opens a recovery session after the bank has
   * re-identified the customer through its own onboarding controls. */
  router.post('/v1/recovery/sessions', authenticateBankClient, async (req: AuthenticatedRequest, res, next) => {
    try {
      if (!req.bankClientId) throw new UnauthorizedError('Missing authenticated bank client');
      const session = await createRecoverySession(sessionSchema.parse(req.body).bankCustomerRef, req.bankClientId);
      res.status(201).json(session);
    } catch (error) {
      next(error);
    }
  });

  /** Device: completes recovery with the phrase proof and a new attested key. */
  router.post('/v1/recovery/sessions/:sessionId/complete', async (req, res, next) => {
    try {
      const token = /^Bearer[ \t]+(\S+)$/.exec(req.header('authorization') ?? '')?.[1];
      if (!token) {
        res.status(401).json({ error: 'Recovery access token required' });
        return;
      }
      const body = completeSchema.parse(req.body);
      const sessionId = z.string().uuid().parse(req.params.sessionId);
      const nonce = await getRecoveryAttestationBinding(sessionId, token);
      const deviceKeys = { authPublicKeyPem: body.authPublicKeyPem, offlinePublicKeyPem: body.offlinePublicKeyPem, offlineKeyAgreement: body.offlineKeyAgreement };
      const binding = buildAttestationBinding(nonce, body.newPublicKeyPem, deviceKeys);
      const verdict = await verifyDeviceAttestation(body.deviceAttestation, binding,
        { challenge: nonce, signingPublicKeyPem: body.newPublicKeyPem, authPublicKeyPem: body.authPublicKeyPem });
      if (!platformMatches(verdict, body.platform)) {
        verdict.verified = false;
        verdict.reason = 'the attestation is from another platform than the one claimed';
      }
      if (env.REQUIRE_VALID_ATTESTATION && !verdict.verified) {
        req.log?.warn({ reason: verdict.reason }, 'Device attestation refused');
        res.status(403).json({ error: 'Device attestation verification failed' });
        return;
      }

      const result = await completeRecovery({
        sessionId,
        accessToken: token,
        proofB64: body.proof,
        newPublicKeyPem: body.newPublicKeyPem,
        platform: body.platform,
        securityLevel: verdict.verified && verdict.securityLevel ? verdict.securityLevel : body.securityLevel,
        attestationStatus: verdict.verified ? 'VERIFIED' : 'UNKNOWN',
        attestation: enrolmentAttestation(body.deviceAttestation, binding, verdict),
        deviceKeys,
        hsm: hsmAdapter,
      });
      res.status(200).json({ ...result, requestAuthentication: 'DEVICE_SIGNATURE' });
    } catch (error) {
      next(error);
    }
  });

  return router;
}
