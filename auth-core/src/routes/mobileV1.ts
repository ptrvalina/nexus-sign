import { Router, type Response } from 'express';
import { z } from 'zod';
import type { HsmAdapter } from '../crypto/hsmAdapter';
import { authenticateBankClient, type AuthenticatedRequest } from '../middleware/auth';
import { authenticateMobileSession, type MobileAuthenticatedRequest } from '../middleware/mobileAuth';
import { consumeMobileSession, issueBootstrapToken, type ReplacementAuthorization } from '../services/mobileSessionService';
import { decideDeviceReplacement, listOpenReplacements, requestDeviceReplacement } from '../services/deviceReplacementService';
import { getNexusIdentityForClient } from '../services/nexusIdentityService';
import { createCredential, getActiveDeviceCredential, getCredentialForClient, hasEnrolledCredential, hasRevokedCredential, revokeDeviceByCustomer } from '../services/credentialService';
import { assertCredentialIntegrity } from '../services/credentialIntegrity';
import { recordAuditEvent } from '../services/auditService';
import { enrolmentAttestation, platformMatches, verifyDeviceAttestation } from '../services/attestationVerificationService';
import { env } from '../config/env';
import { authorizationObjectOf, getAuthorizationForClient, type AuthorizationRecord } from '../services/authorizationRecord';
import { submitDeferredSignature, verifyAuthorization } from '../services/authorizationConfirmation';
import { canonicalizeAuthorization } from '../services/canonicalAuthorization';
import { reportedState } from '../services/authorizationExpiry';
import { beginRecoverySetup, completeRecoverySetup } from '../services/recoveryService';
import { escalateVerification, getVerificationPlan, openVerificationSession } from '../services/adaptiveVerificationService';
import { buildAttestationBinding } from '../services/attestationBinding';
import { registerPushDevice, unregisterPushDevice, type DeviceContext } from '../services/pushRegistrationService';
import { getPushEnvelopeForDevice, recordPushReceipt } from '../services/pushService';
import { deviceCancel, deviceJoin, deviceSignal, deviceSignals } from '../services/verificationCall';
import { byIp, loginThrottle } from '../middleware/bruteForceProtection';
import { ConflictError, ForbiddenError, NotFoundError, UnauthorizedError } from '../services/errors';
import { declineAuthorization } from '../services/authorizationDecline';
import {
  authorizationHistory, evidenceForCustomer, getSettings, listDevices, notificationHistory, securityEvents, suspendByCustomer, updateSettings,
} from '../services/customerAccountService';

const bootstrapSchema = z.object({
  publicKeyPem: z.string().min(1).max(4096),
  platform: z.enum(['IOS', 'ANDROID', 'OTHER']),
  securityLevel: z.string().min(1).max(32),
  /** Hardware key that signs every later request of the device. */
  authPublicKeyPem: z.string().min(1).max(4096),
  /** Biometric-protected key agreement key for offline confirmation. */
  offlinePublicKeyPem: z.string().min(1).max(4096).optional(),
  deviceAttestation: z.record(z.unknown()).default({}),
});

const signatureSchema = z.object({
  signature: z.string().min(1).max(512),
  signatureFormat: z.enum(['der', 'raw']),
});

const authorizationIdParam = z.string().uuid();

// Receipts are unauthenticated apart from their HMAC; a source that sends
// many receipts that do not verify is paused.
const receiptThrottle = loginThrottle({
  keyPrefix: 'push_receipt_failures_ip',
  extractKey: byIp,
  maxFailures: 100,
  windowSeconds: 300,
  lockoutSeconds: 900,
});

interface MobileScope { clientId: string; nexusId: string }

/** The caller's scope if its mobile token has the required purpose. */
function scope(req: MobileAuthenticatedRequest, purpose: 'BOOTSTRAP' | 'DEVICE'): MobileScope {
  if (!req.mobileClientId || !req.mobileNexusId) throw new UnauthorizedError('Mobile session required');
  if (req.mobileSessionPurpose !== purpose) {
    throw new ForbiddenError(purpose === 'DEVICE' ? 'A request signed by the enrolled device is required' : 'A bootstrap token is required');
  }
  return { clientId: req.mobileClientId, nexusId: req.mobileNexusId };
}

/** Loads an authorization and checks it belongs to the session's NEXUS ID. */
async function authorizationInScope(authorizationId: string, s: MobileScope): Promise<AuthorizationRecord> {
  const auth = await getAuthorizationForClient(authorizationIdParam.parse(authorizationId), s.clientId);
  if (auth.nexusId !== s.nexusId) throw new ForbiddenError('Authorization is outside the mobile session scope');
  return auth;
}

/** The enrolled device that signed the request. */
async function deviceInScope(req: MobileAuthenticatedRequest): Promise<DeviceContext> {
  const s = scope(req, 'DEVICE');
  const credential = req.mobileCredentialId ? await getActiveDeviceCredential(req.mobileCredentialId) : null;
  if (!credential || credential.nexusId !== s.nexusId) throw new ForbiddenError('An enrolled device credential is required');
  return { clientId: s.clientId, nexusId: s.nexusId, credentialId: credential.credentialId, platform: credential.platform };
}

const pushRegistrationSchema = z.object({
  provider: z.enum(['APNS', 'FCM']),
  deviceToken: z.string().min(1).max(4096),
  apnsEnvironment: z.enum(['PRODUCTION', 'DEVELOPMENT']).optional(),
  /** Ephemeral P-256 key for (re)agreeing the push key. */
  devicePublicKeyPem: z.string().min(1).max(4096).optional(),
  /** Token refresh: the ID of the push key the device holds. */
  keyId: z.string().regex(/^[A-Za-z0-9_-]{22}$/).optional(),
});

function bearerToken(req: MobileAuthenticatedRequest): string {
  return (req.header('authorization') ?? '').replace(/^Bearer\s+/i, '');
}

export function buildMobileV1Router(hsmAdapter: HsmAdapter): Router {
  const router = Router();

  /**
   * Bank backend: issues a single-use BOOTSTRAP token (300 s) with which the
   * embedded SDK enrols the device. Enrolled devices sign their requests and
   * need no token; `purpose: SESSION` was removed in 2.0.0-rc.2.
   */
  router.post('/v1/mobile/sessions', authenticateBankClient, async (req: AuthenticatedRequest, res: Response, next) => {
    try {
      if (!req.bankClientId) throw new UnauthorizedError('Missing authenticated bank client');
      const body = z.object({
        nexusId: z.string().regex(/^\d{9}$/),
        purpose: z.literal('BOOTSTRAP', { errorMap: () => ({ message: 'Only BOOTSTRAP tokens exist; enrolled devices sign their requests' }) }).default('BOOTSTRAP'),
        /** Required to enrol a device for an identity that already has one:
         * how the bank re-identified the customer, and its case reference. */
        replacement: z.object({
          method: z.enum(['BRANCH_VISIT', 'VIDEO_IDENTIFICATION', 'IN_APP_STRONG_AUTHENTICATION', 'OTHER']),
          reference: z.string().min(1).max(128),
        }).optional(),
        /** Enrols a further device next to the active ones (migration 027),
         * up to the bank client's max_devices_per_identity. */
        addition: z.object({
          method: z.enum(['BRANCH_VISIT', 'VIDEO_IDENTIFICATION', 'IN_APP_STRONG_AUTHENTICATION', 'OTHER']),
          reference: z.string().min(1).max(128),
        }).optional(),
      }).refine((b) => !(b.replacement && b.addition), { message: 'replacement and addition are exclusive' }).parse(req.body);
      const identity = await getNexusIdentityForClient(body.nexusId, req.bankClientId);
      if (identity.status !== 'ACTIVE') throw new ConflictError(`NEXUS ID is ${identity.status}`);
      const enrolled = await hasEnrolledCredential(body.nexusId);
      if (!body.replacement && !body.addition && enrolled) {
        throw new ConflictError(
          'The customer already has an enrolled device. Use recovery with the recovery phrase, or issue a replacement token after re-identifying the customer',
          'ACTIVE_CREDENTIAL_EXISTS');
      }
      // A device that was revoked is replaced like an enrolled one, with the
      // hold, so "revoke, then enrol" is not a way around it (A2-01).
      const hadDevice = !enrolled && await hasRevokedCredential(body.nexusId);
      if (!body.replacement && !body.addition && hadDevice) {
        throw new ConflictError(
          'This NEXUS ID had a device before. Use recovery with the recovery phrase, or request a replacement after re-identifying the customer',
          'REPLACEMENT_REQUIRED');
      }
      const actor = { nexusId: body.nexusId, actor: `bank:${req.bankClientId}`, ipAddress: req.ip, userAgent: req.header('user-agent') };
      let replacement: ReplacementAuthorization | undefined;
      if (body.addition) {
        // A further device waits for an enrolled device's approval, or for
        // the hold, exactly like a replacement; it revokes nothing.
        const { replacement: request } = await requestDeviceReplacement(req.bankClientId, body.nexusId, body.addition.method, body.addition.reference, 'ADDITION');
        if (!request.usable) {
          res.status(202).json({ status: 'ADDITION_PENDING', replacementId: request.replacementId, kind: request.kind, state: request.state, notBefore: request.notBefore, expiresAt: request.expiresAt });
          return;
        }
        replacement = { method: request.method, reference: request.reference, replacementId: request.replacementId, kind: 'ADDITION' };
      } else if (body.replacement && (enrolled || hadDevice)) {
        // A replacement waits for the customer's approval on the enrolled
        // device, or for the hold to pass (deviceReplacementService).
        const { replacement: request } = await requestDeviceReplacement(req.bankClientId, body.nexusId, body.replacement.method, body.replacement.reference);
        if (!request.usable) {
          res.status(202).json({ status: 'REPLACEMENT_PENDING', replacementId: request.replacementId, state: request.state, notBefore: request.notBefore, expiresAt: request.expiresAt });
          return;
        }
        replacement = { method: request.method, reference: request.reference, replacementId: request.replacementId, kind: 'REPLACEMENT' };
      }
      const session = await issueBootstrapToken(req.bankClientId, body.nexusId, replacement);
      await recordAuditEvent('mobile_session_issued', actor, { purpose: body.purpose, expiresIn: session.expiresIn });
      if (replacement) {
        await recordAuditEvent('credential_replacement_authorized', actor, { method: replacement.method, reference: replacement.reference, replacementId: replacement.replacementId });
      }
      res.status(201).json({
        accessToken: session.token,
        tokenType: 'Bearer',
        expiresIn: session.expiresIn,
        nexusId: session.nexusId,
        purpose: session.purpose,
        attestationChallenge: session.attestationChallenge,
      });
    } catch (e) { next(e); }
  });

  /**
   * Delivery receipt from the app or its notification extension, which may
   * run while the phone is locked and cannot use the request-signing key. It
   * is authenticated by the receipt itself, an HMAC under the push key that
   * only this device and Auth Core hold.
   */
  router.post('/v1/push-receipts/:messageId', receiptThrottle.guard, async (req, res, next) => {
    try {
      const body = z.object({ credentialId: z.string().uuid(), receipt: z.string().regex(/^[A-Za-z0-9_-]{43}$/) }).parse(req.body);
      try {
        await recordPushReceipt(z.string().uuid().parse(req.params.messageId), body.credentialId.toLowerCase(), body.receipt);
      } catch (error) {
        if (error instanceof NotFoundError) await receiptThrottle.recordFailure(req).catch(() => undefined);
        throw error;
      }
      res.status(204).send();
    } catch (e) { next(e); }
  });

  // Every route below is called by the SDK with a mobile token. Scoped to
  // /v1/mobile because this router is mounted ahead of the bank routers.
  router.use('/v1/mobile', authenticateMobileSession);

  router.get('/v1/mobile/recovery/setup', async (req: MobileAuthenticatedRequest, res, next) => {
    try {
      const device = await deviceInScope(req);
      res.json(await beginRecoverySetup(device.nexusId, device.clientId, device.credentialId));
    } catch (e) { next(e); }
  });

  /** Recovery protocol 2: registers the recovery public key and the wrapped
   * private key, signed with the biometric signing key. */
  router.post('/v1/mobile/recovery/setup', async (req: MobileAuthenticatedRequest, res, next) => {
    try {
      const device = await deviceInScope(req);
      const body = z.object({
        protocol: z.literal(2),
        salt: z.string().min(20).max(64),
        recoveryPublicKeyPem: z.string().min(1).max(4096),
        wrappedRecoveryKey: z.string().min(80).max(128),
        signature: z.string().min(1).max(512),
      }).parse(req.body);
      const credential = await getCredentialForClient(device.credentialId, device.clientId);
      await assertCredentialIntegrity(credential);
      await completeRecoverySetup({
        nexusId: device.nexusId, clientId: device.clientId, credential, saltB64: body.salt,
        recoveryPublicKeyPem: body.recoveryPublicKeyPem, wrappedRecoveryKeyB64: body.wrappedRecoveryKey, signatureB64: body.signature, hsm: hsmAdapter,
      });
      res.status(204).send();
    } catch (e) { next(e); }
  });

  router.post('/v1/mobile/bootstrap', async (req: MobileAuthenticatedRequest, res, next) => {
    try {
      const s = scope(req, 'BOOTSTRAP');
      const body = bootstrapSchema.parse(req.body);
      if (!req.mobileAttestationChallenge) throw new ForbiddenError('Bootstrap attestation challenge is missing or expired');
      const challenge = Buffer.from(req.mobileAttestationChallenge, 'base64url');
      const deviceKeys = { authPublicKeyPem: body.authPublicKeyPem, offlinePublicKeyPem: body.offlinePublicKeyPem };
      const binding = buildAttestationBinding(challenge, body.publicKeyPem, deviceKeys);
      const verdict = await verifyDeviceAttestation(body.deviceAttestation, binding,
        { challenge, signingPublicKeyPem: body.publicKeyPem, authPublicKeyPem: body.authPublicKeyPem });
      if (!platformMatches(verdict, body.platform)) {
        verdict.verified = false;
        verdict.reason = 'the attestation is from another platform than the one claimed';
      }
      if (env.REQUIRE_VALID_ATTESTATION && !verdict.verified) {
        req.log?.warn({ reason: verdict.reason }, 'Device attestation refused');
        res.status(403).json({ error: 'Device attestation verification failed' });
        return;
      }
      // Single use, atomically: two concurrent requests with one bootstrap
      // token cannot both enrol a key.
      if (!(await consumeMobileSession(bearerToken(req)))) throw new ConflictError('Bootstrap token has already been used');

      const credential = await createCredential({
        nexusId: s.nexusId,
        publicKeyPem: body.publicKeyPem,
        platform: body.platform,
        // Proven by the attestation when it is verified; the client's claim
        // is kept only where attestation is not required (development).
        securityLevel: verdict.verified && verdict.securityLevel ? verdict.securityLevel : body.securityLevel,
        attestationStatus: verdict.verified ? 'VERIFIED' : 'UNKNOWN',
        clientId: s.clientId,
        replacement: req.mobileReplacement ?? null,
        deviceKeys,
        hsm: hsmAdapter,
        enrolment: { reason: req.mobileReplacement ? (req.mobileReplacement.kind === 'ADDITION' ? 'ADDITION' : 'REPLACEMENT') : 'ENROLMENT', attestation: enrolmentAttestation(body.deviceAttestation, binding, verdict) },
      });
      // The device signs its own requests from now on: no token is issued.
      res.status(201).json({
        nexusId: s.nexusId,
        credentialId: credential.credentialId,
        credentialState: credential.state,
        keyAlgorithm: credential.keyAlgorithm,
        keyVersion: credential.keyVersion,
        attestationStatus: credential.attestationStatus,
        requestAuthentication: 'DEVICE_SIGNATURE',
        offlineServerPublicKeyPem: credential.offlineServerPublicKeyPem,
      });
    } catch (e) { next(e); }
  });

  /** The authorization with the exact bytes the device signs. The SDK
   * verifies every other field against `canonicalPayloadBase64`. */
  router.get('/v1/mobile/authorizations/:authorizationId', async (req: MobileAuthenticatedRequest, res, next) => {
    try {
      const auth = await authorizationInScope(req.params.authorizationId, scope(req, 'DEVICE'));
      res.json({
        authorizationId: auth.authorizationId,
        nexusId: auth.nexusId,
        credentialId: auth.credentialId,
        transactionReference: auth.transactionReference,
        operationType: auth.operationType,
        amountMinor: auth.amountMinor,
        currency: auth.currency,
        beneficiary: auth.beneficiary,
        policyReference: auth.policyReference,
        policyVersion: auth.policyVersion,
        canonicalPayloadHash: auth.canonicalPayloadHash,
        nonce: auth.nonce,
        issuedAt: auth.issuedAt.toISOString(),
        expiresAt: auth.expiresAt.toISOString(),
        state: reportedState(auth),
        signatureAlgorithm: auth.signatureAlgorithm,
        verifiedAt: auth.verifiedAt?.toISOString() ?? null,
        canonicalPayloadBase64: canonicalizeAuthorization(authorizationObjectOf(auth)).toString('base64'),
      });
    } catch (e) { next(e); }
  });

  router.get('/v1/mobile/authorizations/:authorizationId/verification-plan', async (req: MobileAuthenticatedRequest, res, next) => {
    try {
      const s = scope(req, 'DEVICE');
      const auth = await authorizationInScope(req.params.authorizationId, s);
      res.json(await getVerificationPlan(auth.authorizationId, s.clientId));
    } catch (e) { next(e); }
  });

  /** The customer asks for a stronger check than the policy requires. */
  router.post('/v1/mobile/authorizations/:authorizationId/verification/escalate', async (req: MobileAuthenticatedRequest, res, next) => {
    try {
      const s = scope(req, 'DEVICE');
      const auth = await authorizationInScope(req.params.authorizationId, s);
      res.json(await escalateVerification(auth.authorizationId, s.clientId, 'CLIENT_REQUEST'));
    } catch (e) { next(e); }
  });

  router.post('/v1/mobile/authorizations/:authorizationId/verification-sessions', async (req: MobileAuthenticatedRequest, res, next) => {
    try {
      const s = scope(req, 'DEVICE');
      const auth = await authorizationInScope(req.params.authorizationId, s);
      const body = z.object({ channel: z.enum(['AUDIO', 'VIDEO']) }).parse(req.body);
      res.status(201).json(await openVerificationSession(auth.authorizationId, s.clientId, body.channel));
    } catch (e) { next(e); }
  });

  // --- In-app audio/video call (ADR 0017): WebRTC signalling relay ---

  const callDevice = async (req: MobileAuthenticatedRequest) => {
    const device = await deviceInScope(req);
    return { clientId: device.clientId, nexusId: device.nexusId, credentialId: device.credentialId };
  };
  const sessionParam = z.string().uuid();

  /** ICE servers and state of an open session of this device's authorization. */
  router.get('/v1/mobile/verification-sessions/:sessionId/call', async (req: MobileAuthenticatedRequest, res, next) => {
    try {
      res.json(await deviceJoin(sessionParam.parse(req.params.sessionId), await callDevice(req)));
    } catch (e) { next(e); }
  });

  router.post('/v1/mobile/verification-sessions/:sessionId/signals', async (req: MobileAuthenticatedRequest, res, next) => {
    try {
      const body = z.object({ type: z.string(), payload: z.unknown().optional(), messageId: z.string().uuid().optional() }).strict().parse(req.body);
      const sent = await deviceSignal(sessionParam.parse(req.params.sessionId), await callDevice(req), body.type, body.payload ?? null, body.messageId);
      res.status(sent.duplicate ? 200 : 201).json(sent);
    } catch (e) { next(e); }
  });

  /** Signals from the operator with seq > after; waits up to waitMs (long poll). */
  router.get('/v1/mobile/verification-sessions/:sessionId/signals', async (req: MobileAuthenticatedRequest, res, next) => {
    try {
      const query = z.object({ after: z.coerce.number().int().nonnegative().default(0), waitMs: z.coerce.number().int().min(0).max(20_000).default(0) }).parse(req.query);
      res.json(await deviceSignals(sessionParam.parse(req.params.sessionId), await callDevice(req), query.after, query.waitMs));
    } catch (e) { next(e); }
  });

  /** The customer ends or declines the call; nothing is verified or failed. */
  router.post('/v1/mobile/verification-sessions/:sessionId/cancel', async (req: MobileAuthenticatedRequest, res, next) => {
    try {
      await deviceCancel(sessionParam.parse(req.params.sessionId), await callDevice(req));
      res.status(204).send();
    } catch (e) { next(e); }
  });

  // --- Device replacement (the enrolled device decides) ---

  /** Open replacement requests for this device's NEXUS ID, to show to the customer. */
  router.get('/v1/mobile/device-replacements', async (req: MobileAuthenticatedRequest, res, next) => {
    try {
      const device = await deviceInScope(req);
      res.json({ replacements: await listOpenReplacements(device.nexusId) });
    } catch (e) { next(e); }
  });

  const replacementParam = z.string().uuid();
  const decideReplacement = (decision: 'APPROVE' | 'CANCEL') => async (req: MobileAuthenticatedRequest, res: Response, next: (e?: unknown) => void) => {
    try {
      const device = await deviceInScope(req);
      res.json(await decideDeviceReplacement(device.credentialId, device.nexusId, replacementParam.parse(req.params.replacementId), decision));
    } catch (e) { next(e); }
  };
  /** The customer approves a replacement on the enrolled device: the hold ends now. */
  router.post('/v1/mobile/device-replacements/:replacementId/approve', decideReplacement('APPROVE'));
  /** The customer cancels a replacement on the enrolled device ("it wasn't me"). */
  router.post('/v1/mobile/device-replacements/:replacementId/cancel', decideReplacement('CANCEL'));

  // --- The customer's own section in the bank's app (presentation pages 19-22) ---

  const page = z.object({ before: z.string().datetime().optional(), limit: z.coerce.number().int().min(1).max(200).optional() });

  /** "My devices": every device that held keys for this NEXUS ID. */
  router.get('/v1/mobile/devices', async (req: MobileAuthenticatedRequest, res, next) => {
    try {
      const device = await deviceInScope(req);
      res.json({ devices: await listDevices(device.nexusId, device.credentialId) });
    } catch (e) { next(e); }
  });

  /** The customer removes one of their devices (itself or another one). */
  router.post('/v1/mobile/devices/:credentialId/revoke', async (req: MobileAuthenticatedRequest, res, next) => {
    try {
      const device = await deviceInScope(req);
      const target = z.string().uuid().parse(req.params.credentialId).toLowerCase();
      const result = await revokeDeviceByCustomer(device.clientId, device.nexusId, device.credentialId, target);
      res.json({ credentialId: target, state: 'REVOKED', remainingActiveDevices: result.remainingActive });
    } catch (e) { next(e); }
  });

  /** Confirmations, declines and open requests, newest first. */
  router.get('/v1/mobile/history', async (req: MobileAuthenticatedRequest, res, next) => {
    try {
      const device = await deviceInScope(req);
      const q = page.extend({ filter: z.enum(['all', 'confirmed', 'declined', 'open']).optional() }).parse(req.query);
      res.json({ authorizations: await authorizationHistory(device.nexusId, q) });
    } catch (e) { next(e); }
  });

  /** The sealed evidence of one of the customer's authorizations. */
  router.get('/v1/mobile/authorizations/:authorizationId/evidence', async (req: MobileAuthenticatedRequest, res, next) => {
    try {
      const device = await deviceInScope(req);
      const auth = await authorizationInScope(req.params.authorizationId, device);
      res.json(await evidenceForCustomer(device.nexusId, auth.authorizationId));
    } catch (e) { next(e); }
  });

  /** The identity's security log. */
  router.get('/v1/mobile/security-events', async (req: MobileAuthenticatedRequest, res, next) => {
    try {
      const device = await deviceInScope(req);
      res.json({ events: await securityEvents(device.nexusId, page.parse(req.query)) });
    } catch (e) { next(e); }
  });

  /** Past notifications (the event feed); each opens with GET /v1/mobile/push-messages/{id}. */
  router.get('/v1/mobile/notifications', async (req: MobileAuthenticatedRequest, res, next) => {
    try {
      const device = await deviceInScope(req);
      res.json({ notifications: await notificationHistory(device.nexusId, page.parse(req.query)) });
    } catch (e) { next(e); }
  });

  router.get('/v1/mobile/settings', async (req: MobileAuthenticatedRequest, res, next) => {
    try {
      const device = await deviceInScope(req);
      res.json(await getSettings(device.nexusId));
    } catch (e) { next(e); }
  });

  const amount = z.string().regex(/^(0|[1-9]\d{0,29})$/).nullable();
  /** Limits, video-check threshold and channels; relaxing changes wait CUSTOMER_SETTINGS_RELAX_HOLD_SECONDS. */
  router.put('/v1/mobile/settings', async (req: MobileAuthenticatedRequest, res, next) => {
    try {
      const device = await deviceInScope(req);
      const body = z.object({
        currency: z.string().regex(/^[A-Z]{3}$/).nullable(),
        perPaymentLimitMinor: amount, dailyLimitMinor: amount, videoCheckAboveMinor: amount,
        channels: z.object({ push: z.boolean(), audio: z.boolean(), video: z.boolean() }).strict(),
      }).strict().parse(req.body);
      res.json(await updateSettings(device.clientId, device.nexusId, device.credentialId, body));
    } catch (e) { next(e); }
  });

  /** The customer suspends their NEXUS ID; the bank reactivates it after re-identification. */
  router.post('/v1/mobile/identity/suspend', async (req: MobileAuthenticatedRequest, res, next) => {
    try {
      const device = await deviceInScope(req);
      const body = z.object({ reason: z.enum(['LOST_DEVICE', 'SUSPECTED_FRAUD', 'OTHER']) }).strict().parse(req.body);
      await suspendByCustomer(device.clientId, device.nexusId, device.credentialId, body.reason);
      res.json({ nexusId: device.nexusId, status: 'SUSPENDED' });
    } catch (e) { next(e); }
  });

  // --- Secure push ---

  /** Registers or refreshes this device's APNs or FCM token; with
   * devicePublicKeyPem, also agrees a new push key. */
  router.post('/v1/mobile/push-registration', async (req: MobileAuthenticatedRequest, res, next) => {
    try {
      const device = await deviceInScope(req);
      res.json(await registerPushDevice(device, pushRegistrationSchema.parse(req.body)));
    } catch (e) { next(e); }
  });

  router.delete('/v1/mobile/push-registration', async (req: MobileAuthenticatedRequest, res, next) => {
    try {
      await unregisterPushDevice(await deviceInScope(req));
      res.status(204).send();
    } catch (e) { next(e); }
  });

  /** The sealed message, when the app opens before the push arrives. */
  router.get('/v1/mobile/push-messages/:messageId', async (req: MobileAuthenticatedRequest, res, next) => {
    try {
      const device = await deviceInScope(req);
      res.json(await getPushEnvelopeForDevice(z.string().uuid().parse(req.params.messageId), device.credentialId));
    } catch (e) { next(e); }
  });

  router.post('/v1/mobile/authorizations/:authorizationId/signature', async (req: MobileAuthenticatedRequest, res, next) => {
    try {
      const s = scope(req, 'DEVICE');
      const auth = await authorizationInScope(req.params.authorizationId, s);
      const body = signatureSchema.parse(req.body);
      const result = await verifyAuthorization(hsmAdapter, auth.authorizationId, s.clientId, body.signature, body.signatureFormat,
        { ipAddress: req.ip, userAgent: req.header('user-agent') });
      res.status(result.status === 'EXPIRED' ? 410 : 200).json(result);
    } catch (e) { next(e); }
  });

  /** Offline confirmation v2: the device's signature over the bytes
   * it confirmed offline, uploaded once it has a connection. Only from the
   * credential the authorization names. 200 VERIFIED or ALREADY_RECORDED,
   * 202 RECEIVED (the code has not arrived yet), 409 NOT_AWAITING_SIGNATURE,
   * 422 INVALID_DEFERRED_SIGNATURE. */
  /** The customer declines the payment on the enrolled device ("it wasn't me"). */
  router.post('/v1/mobile/authorizations/:authorizationId/decline', async (req: MobileAuthenticatedRequest, res, next) => {
    try {
      const device = await deviceInScope(req);
      const auth = await authorizationInScope(req.params.authorizationId, device);
      const body = z.object({ reason: z.enum(['NOT_ME', 'WRONG_DETAILS', 'OTHER']) }).parse(req.body);
      res.json(await declineAuthorization(auth.authorizationId, device.clientId, device.credentialId, body.reason,
        { ipAddress: req.ip, userAgent: req.header('user-agent') }));
    } catch (e) { next(e); }
  });

  router.post('/v1/mobile/authorizations/:authorizationId/deferred-signature', async (req: MobileAuthenticatedRequest, res, next) => {
    try {
      const device = await deviceInScope(req);
      const auth = await authorizationInScope(req.params.authorizationId, device);
      const body = signatureSchema.parse(req.body);
      const result = await submitDeferredSignature(hsmAdapter, auth.authorizationId, device.clientId, device.credentialId,
        body.signature, body.signatureFormat, { ipAddress: req.ip, userAgent: req.header('user-agent') });
      res.status(result.status === 'RECEIVED' ? 202 : 200).json(result);
    } catch (e) { next(e); }
  });

  return router;
}
