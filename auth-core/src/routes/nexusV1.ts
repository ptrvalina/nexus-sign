import { Router } from 'express';
import { z } from 'zod';
import type { AuthenticatedRequest } from '../middleware/auth';
import { createNexusIdentity, getNexusIdentityForClient, reactivateNexusIdentity, suspendNexusIdentity } from '../services/nexusIdentityService';
import { getSettings, listDevices } from '../services/customerAccountService';
import { getCredentialForClient, revokeCredentialForClient } from '../services/credentialService';
import { createAuthorization } from '../services/authorizationService';
import { getAuthorizationForClient } from '../services/authorizationRecord';
import { reportedState } from '../services/authorizationExpiry';
import { confirmationView } from '../services/authorizationEvidenceCheck';
import { confirmAuthorizationOffline, getOfflineChallenge, verifyAuthorization } from '../services/authorizationConfirmation';
import { finalizeBankTransaction, getBankTransactionState, requestCommit } from '../services/bankTransactionService';
import { cancelAuthorizationByBank } from '../services/authorizationDecline';
import { completeVerificationSession, escalateVerification, getVerificationPlan, openVerificationSession } from '../services/adaptiveVerificationService';
import { getAuthorizationEvidencePosition, getChainHead, getEvidenceChain, getEvidenceForAuthorization } from '../services/evidenceService';
import { evidencePublicKeys } from '../services/credentialIntegrity';
import { pool } from '../db/pool';
import { getPushMessageForClient, sendPushMessage, type PushMessageRecord } from '../services/pushService';
import { PUSH_BODY_MAX, PUSH_CATEGORIES, PUSH_DATA_KEY_PATTERN, PUSH_DATA_MAX_FIELDS, PUSH_DATA_VALUE_MAX, PUSH_TITLE_MAX } from '../services/pushProtocol';
import type { HsmAdapter } from '../crypto/hsmAdapter';
import { requireGatewayMtls } from '../middleware/mtlsGateway';
import { env } from '../config/env';
import { BENEFICIARY_KEY_PATTERN, BENEFICIARY_MAX_FIELDS, BENEFICIARY_MAX_VALUE_LENGTH } from '../services/canonicalAuthorization';
import { UnauthorizedError, ValidationError } from '../services/errors';

const nexusIdSchema = z.string().regex(/^\d{9}$/);
const uuidSchema = z.string().uuid();

const authorizationSchema = z.object({
  nexusId: nexusIdSchema,
  credentialId: uuidSchema,
  transactionReference: z.string().min(1).max(128),
  operationType: z.string().min(1).max(32),
  amountMinor: z.string().regex(/^(0|[1-9]\d{0,29})$/),
  currency: z.string().regex(/^[A-Z]{3}$/),
  beneficiary: z.record(z.string().regex(BENEFICIARY_KEY_PATTERN), z.string().max(BENEFICIARY_MAX_VALUE_LENGTH))
    .refine((b) => Object.keys(b).length <= BENEFICIARY_MAX_FIELDS, { message: `at most ${BENEFICIARY_MAX_FIELDS} beneficiary fields` }),
  policyReference: z.string().min(1).max(128),
  policyVersion: z.string().min(1).max(64),
  verificationPolicy: z.object({
    pushTimeoutSeconds: z.number().int().min(10).max(300).optional(),
    highAmountThresholdMinor: z.string().regex(/^\d{1,30}$/).optional(),
    requireAudio: z.boolean().optional(),
    requireVideo: z.boolean().optional(),
    audioAvailable: z.boolean().optional(),
    videoAvailable: z.boolean().optional(),
    clientEscalationAllowed: z.boolean().optional(),
  }).optional(),
  expiresInSeconds: z.number().int().min(30).max(900).optional(),
  correlationId: z.string().max(128).optional(),
  /** Secure push text (push mode NEXUS). Only invites the customer to open the app. */
  pushNotification: z.object({
    title: z.string().min(1).max(PUSH_TITLE_MAX).optional(),
    body: z.string().max(PUSH_BODY_MAX).optional(),
  }).optional(),
});

const bankPushCategories = PUSH_CATEGORIES.filter((c): c is Exclude<typeof c, 'AUTHORIZATION_REQUEST'> => c !== 'AUTHORIZATION_REQUEST');

const pushMessageSchema = z.object({
  nexusId: nexusIdSchema,
  category: z.enum(bankPushCategories as [typeof bankPushCategories[number], ...typeof bankPushCategories]),
  title: z.string().min(1).max(PUSH_TITLE_MAX),
  body: z.string().max(PUSH_BODY_MAX).optional(),
  data: z.record(z.string().regex(PUSH_DATA_KEY_PATTERN), z.string().max(PUSH_DATA_VALUE_MAX))
    .refine((d) => Object.keys(d).length <= PUSH_DATA_MAX_FIELDS, { message: `at most ${PUSH_DATA_MAX_FIELDS} data fields` })
    .optional(),
  ttlSeconds: z.number().int().min(60).max(2_419_200).optional(),
  messageReference: z.string().min(1).max(128).optional(),
});

function pushMessageView(message: PushMessageRecord): Record<string, unknown> {
  return {
    messageId: message.messageId,
    nexusId: message.nexusId,
    category: message.category,
    authorizationId: message.authorizationId,
    messageReference: message.messageReference,
    status: message.status,
    provider: message.provider,
    retryCount: message.retryCount,
    lastError: message.lastError,
    createdAt: message.createdAt.toISOString(),
    sentAt: message.sentAt?.toISOString() ?? null,
    deliveredAt: message.deliveredAt?.toISOString() ?? null,
    expiresAt: message.expiresAt.toISOString(),
  };
}

const signatureSchema = z.object({ signature: z.string().min(1).max(512), signatureFormat: z.enum(['der', 'raw']) });

function clientIdOf(req: AuthenticatedRequest): string {
  if (!req.bankClientId) throw new UnauthorizedError('Missing authenticated bank client');
  return req.bankClientId;
}

export function buildNexusV1Router(hsmAdapter: HsmAdapter): Router {
  const router = Router();

  // --- Identities and credentials ---

  router.post('/v1/nexus-identities', async (req: AuthenticatedRequest, res, next) => {
    try {
      const body = z.object({ bankCustomerRef: z.string().min(1).max(128) }).parse(req.body);
      const identity = await createNexusIdentity(clientIdOf(req), body.bankCustomerRef);
      // 200 with replayed=true: the identity already existed for this
      // customer reference (a retry after a lost response).
      res.status(identity.replayed ? 200 : 201).json({
        nexusId: identity.nexusId, status: identity.status, createdAt: identity.createdAt.toISOString(), replayed: identity.replayed,
      });
    } catch (e) { next(e); }
  });

  router.get('/v1/nexus-identities/:nexusId', async (req: AuthenticatedRequest, res, next) => {
    try {
      const identity = await getNexusIdentityForClient(nexusIdSchema.parse(req.params.nexusId), clientIdOf(req));
      res.json({
        nexusId: identity.nexusId,
        bankCustomerRef: identity.bankCustomerRef,
        status: identity.status,
        createdAt: identity.createdAt.toISOString(),
        lastUsedAt: identity.lastUsedAt?.toISOString() ?? null,
        evidenceHead: await getChainHead(pool, identity.nexusId),
      });
    } catch (e) { next(e); }
  });

  // --- Suspension by the bank (lost phone reported by phone, fraud) ---

  router.post('/v1/nexus-identities/:nexusId/suspend', async (req: AuthenticatedRequest, res, next) => {
    try {
      const identity = await getNexusIdentityForClient(nexusIdSchema.parse(req.params.nexusId), clientIdOf(req));
      const body = z.object({ reason: z.string().min(1).max(128) }).strict().parse(req.body);
      await suspendNexusIdentity(identity.nexusId, `BANK:${body.reason}`, `bank:${clientIdOf(req)}`);
      res.json({ nexusId: identity.nexusId, status: 'SUSPENDED' });
    } catch (e) { next(e); }
  });

  /** After the bank re-identified the customer (method and the bank's case reference are audited). */
  router.post('/v1/nexus-identities/:nexusId/reactivate', async (req: AuthenticatedRequest, res, next) => {
    try {
      const identity = await getNexusIdentityForClient(nexusIdSchema.parse(req.params.nexusId), clientIdOf(req));
      const body = z.object({
        reidentification: z.object({ method: z.enum(['BRANCH_VISIT', 'VIDEO_IDENTIFICATION', 'IN_APP_STRONG_AUTHENTICATION', 'OTHER']), reference: z.string().min(1).max(128) }).strict(),
      }).strict().parse(req.body);
      await reactivateNexusIdentity(identity.nexusId, `BANK:${body.reidentification.method}:${body.reidentification.reference}`, `bank:${clientIdOf(req)}`);
      res.json({ nexusId: identity.nexusId, status: 'ACTIVE' });
    } catch (e) { next(e); }
  });

  /** The identity's devices, for the bank's support and console. */
  router.get('/v1/nexus-identities/:nexusId/devices', async (req: AuthenticatedRequest, res, next) => {
    try {
      const identity = await getNexusIdentityForClient(nexusIdSchema.parse(req.params.nexusId), clientIdOf(req));
      res.json({ devices: await listDevices(identity.nexusId, '') });
    } catch (e) { next(e); }
  });

  /** The customer's settings and limits (the bank applies its own on top). */
  router.get('/v1/nexus-identities/:nexusId/settings', async (req: AuthenticatedRequest, res, next) => {
    try {
      const identity = await getNexusIdentityForClient(nexusIdSchema.parse(req.params.nexusId), clientIdOf(req));
      res.json(await getSettings(identity.nexusId));
    } catch (e) { next(e); }
  });

  router.get('/v1/nexus-identities/:nexusId/evidence', async (req: AuthenticatedRequest, res, next) => {
    try {
      const page = z.object({
        after: z.coerce.number().int().nonnegative().optional(),
        limit: z.coerce.number().int().min(1).max(1000).optional(),
      }).parse(req.query);
      const nexusId = nexusIdSchema.parse(req.params.nexusId);
      const records = await getEvidenceChain(nexusId, clientIdOf(req), page);
      res.json({
        nexusId,
        records,
        head: await getChainHead(pool, nexusId),
        evidencePublicKeyPem: await hsmAdapter.evidencePublicKeyPem(),
        evidencePublicKeys: await evidencePublicKeys(),
      });
    } catch (e) { next(e); }
  });

  router.get('/v1/credentials/:credentialId', async (req: AuthenticatedRequest, res, next) => {
    try {
      const credential = await getCredentialForClient(uuidSchema.parse(req.params.credentialId), clientIdOf(req));
      res.json({
        credentialId: credential.credentialId,
        nexusId: credential.nexusId,
        state: credential.state,
        keyAlgorithm: credential.keyAlgorithm,
        keyVersion: credential.keyVersion,
        platform: credential.platform,
        securityLevel: credential.securityLevel,
        attestationStatus: credential.attestationStatus,
        offlineEnabled: credential.offlineEnabled,
        deviceSignedRequests: credential.authPublicKeyPem !== null,
        createdAt: credential.createdAt.toISOString(),
        lastUsedAt: credential.lastUsedAt?.toISOString() ?? null,
      });
    } catch (e) { next(e); }
  });

  router.post('/v1/credentials/:credentialId/revoke', async (req: AuthenticatedRequest, res, next) => {
    try {
      const credentialId = uuidSchema.parse(req.params.credentialId);
      const body = z.object({ reason: z.string().min(1).max(256) }).parse(req.body);
      await revokeCredentialForClient(credentialId, clientIdOf(req), body.reason);
      res.json({ credentialId, state: 'REVOKED' });
    } catch (e) { next(e); }
  });

  // --- Authorizations ---

  router.post('/v1/authorizations', async (req: AuthenticatedRequest, res, next) => {
    try {
      const body = authorizationSchema.parse(req.body);
      const idempotencyKey = req.header('Idempotency-Key')?.trim() || undefined;
      if (idempotencyKey && idempotencyKey.length > 128) throw new ValidationError('Idempotency-Key must be at most 128 characters');
      if (env.REQUIRE_IDEMPOTENCY_KEY && !idempotencyKey) throw new ValidationError('Idempotency-Key header is required');

      const { authorization: auth, plan, push, replayed } = await createAuthorization({ ...body, idempotencyKey }, clientIdOf(req));
      res.status(replayed ? 200 : 201).json({
        authorizationId: auth.authorizationId,
        nexusId: auth.nexusId,
        credentialId: auth.credentialId,
        transactionReference: auth.transactionReference,
        canonicalPayloadHash: auth.canonicalPayloadHash,
        issuedAt: auth.issuedAt.toISOString(),
        expiresAt: auth.expiresAt.toISOString(),
        state: auth.state,
        verificationPlan: plan,
        push: push ? { messageId: push.messageId, status: push.status, lastError: push.lastError } : null,
        protocolVersion: '1',
        domain: 'NEXUS-SIGN/TRANSACTION-AUTH',
      });
    } catch (e) { next(e); }
  });

  router.get('/v1/authorizations/:authorizationId', async (req: AuthenticatedRequest, res, next) => {
    try {
      const auth = await getAuthorizationForClient(uuidSchema.parse(req.params.authorizationId), clientIdOf(req));
      res.json({
        ...auth,
        state: reportedState(auth),
        // True only for VERIFIED with sealed evidence that verifies now (HSM
        // seal, binding, terms, device signature with the enrolment key): the
        // state column alone does not set it. OFFLINE_PROVISIONAL never.
        ...(await confirmationView(auth.authorizationId, clientIdOf(req), reportedState(auth))),
        issuedAt: auth.issuedAt.toISOString(),
        expiresAt: auth.expiresAt.toISOString(),
        verifiedAt: auth.verifiedAt?.toISOString() ?? null,
        evidence: await getAuthorizationEvidencePosition(auth.authorizationId),
      });
    } catch (e) { next(e); }
  });

  router.post('/v1/authorizations/:authorizationId/signature', async (req: AuthenticatedRequest, res, next) => {
    try {
      const body = signatureSchema.parse(req.body);
      const result = await verifyAuthorization(hsmAdapter, uuidSchema.parse(req.params.authorizationId), clientIdOf(req),
        body.signature, body.signatureFormat, { ipAddress: req.ip, userAgent: req.header('user-agent') });
      res.status(result.status === 'EXPIRED' ? 410 : 200).json(result);
    } catch (e) { next(e); }
  });

  // --- Offline confirmation ---

  /** QR content for a bank screen (branch, ATM, web banking). The phone reads
   * it without network, shows the transaction and derives an 8-digit code. */
  router.get('/v1/authorizations/:authorizationId/offline-challenge', async (req: AuthenticatedRequest, res, next) => {
    try {
      res.json(await getOfflineChallenge(uuidSchema.parse(req.params.authorizationId), clientIdOf(req)));
    } catch (e) { next(e); }
  });

  /** The code the customer typed on the bank screen. Shares the attempt limit
   * with device signatures. */
  router.post('/v1/authorizations/:authorizationId/offline-confirmation', async (req: AuthenticatedRequest, res, next) => {
    try {
      const body = z.object({ code: z.string().regex(/^\d{8}$/) }).parse(req.body);
      const result = await confirmAuthorizationOffline(hsmAdapter, uuidSchema.parse(req.params.authorizationId), clientIdOf(req),
        body.code, { ipAddress: req.ip, userAgent: req.header('user-agent') });
      res.status(result.status === 'EXPIRED' ? 410 : 200).json(result);
    } catch (e) { next(e); }
  });

  router.get('/v1/authorizations/:authorizationId/evidence', async (req: AuthenticatedRequest, res, next) => {
    try {
      const record = await getEvidenceForAuthorization(uuidSchema.parse(req.params.authorizationId), clientIdOf(req));
      res.json({ ...record, evidencePublicKeyPem: await hsmAdapter.evidencePublicKeyPem(), evidencePublicKeys: await evidencePublicKeys() });
    } catch (e) { next(e); }
  });

  // --- Adaptive verification ---

  router.get('/v1/authorizations/:authorizationId/verification-plan', async (req: AuthenticatedRequest, res, next) => {
    try {
      res.json(await getVerificationPlan(uuidSchema.parse(req.params.authorizationId), clientIdOf(req)));
    } catch (e) { next(e); }
  });

  router.post('/v1/authorizations/:authorizationId/verification/escalate', async (req: AuthenticatedRequest, res, next) => {
    try {
      const body = z.object({
        reason: z.enum(['PUSH_NOT_DELIVERED', 'PUSH_TIMEOUT', 'HIGH_AMOUNT', 'RISK_POLICY', 'CLIENT_REQUEST', 'CHANNEL_FAILURE']),
        requestedStep: z.enum(['AUDIO', 'VIDEO']).optional(),
      }).parse(req.body);
      res.json(await escalateVerification(uuidSchema.parse(req.params.authorizationId), clientIdOf(req), body.reason, body.requestedStep));
    } catch (e) { next(e); }
  });

  router.post('/v1/authorizations/:authorizationId/verification-sessions', async (req: AuthenticatedRequest, res, next) => {
    try {
      const body = z.object({ channel: z.enum(['AUDIO', 'VIDEO']) }).parse(req.body);
      res.status(201).json(await openVerificationSession(uuidSchema.parse(req.params.authorizationId), clientIdOf(req), body.channel));
    } catch (e) { next(e); }
  });

  /** Result of an audio/video check: a result token (JWS) signed by a
   * verification provider registered for this bank, relayed by the
   * bank's verification gateway. Requires gateway mTLS whenever
   * REQUIRE_MTLS_HEADER is set. */
  router.post('/v1/authorizations/:authorizationId/verification-sessions/:sessionId/complete', requireGatewayMtls, async (req: AuthenticatedRequest, res, next) => {
    try {
      const body = z.object({ resultToken: z.string().min(1).max(8192) }).strict().parse(req.body);
      res.json(await completeVerificationSession(uuidSchema.parse(req.params.authorizationId), clientIdOf(req),
        uuidSchema.parse(req.params.sessionId), body.resultToken));
    } catch (e) { next(e); }
  });

  // --- Secure push (push mode NEXUS) ---

  /** A message for the customer's device: incoming payment, card spending,
   * account or security notice. Sealed for the device before it is stored. */
  router.post('/v1/push-messages', async (req: AuthenticatedRequest, res, next) => {
    try {
      const body = pushMessageSchema.parse(req.body);
      const { message, replayed } = await sendPushMessage(clientIdOf(req), body);
      res.status(replayed ? 200 : 202).json(pushMessageView(message));
    } catch (e) { next(e); }
  });

  router.get('/v1/push-messages/:messageId', async (req: AuthenticatedRequest, res, next) => {
    try {
      res.json(pushMessageView(await getPushMessageForClient(uuidSchema.parse(req.params.messageId), clientIdOf(req))));
    } catch (e) { next(e); }
  });

  // --- Bank transaction ---

  /** The bank withdraws an authorization the customer has not confirmed. */
  router.post('/v1/authorizations/:authorizationId/cancel', async (req: AuthenticatedRequest, res, next) => {
    try {
      const body = z.object({ reason: z.enum(['ORDER_CHANGED', 'FRAUD_SUSPECTED', 'CUSTOMER_REQUEST', 'OTHER']) }).parse(req.body);
      res.json(await cancelAuthorizationByBank(uuidSchema.parse(req.params.authorizationId), clientIdOf(req), body.reason,
        { actor: `bank:${clientIdOf(req)}`, ipAddress: req.ip, userAgent: req.header('user-agent') }));
    } catch (e) { next(e); }
  });

  router.post('/v1/authorizations/:authorizationId/bank-commit-request', async (req: AuthenticatedRequest, res, next) => {
    try {
      const body = z.object({ bankTransactionReference: z.string().min(1).max(128) }).parse(req.body);
      res.status(202).json(await requestCommit(uuidSchema.parse(req.params.authorizationId), clientIdOf(req), body.bankTransactionReference));
    } catch (e) { next(e); }
  });

  router.post('/v1/authorizations/:authorizationId/bank-commit-result', async (req: AuthenticatedRequest, res, next) => {
    try {
      const body = z.object({ state: z.enum(['COMMITTED', 'FAILED', 'CANCELLED']), error: z.string().max(256).optional() }).parse(req.body);
      res.json(await finalizeBankTransaction(uuidSchema.parse(req.params.authorizationId), clientIdOf(req), body.state, body.error));
    } catch (e) { next(e); }
  });

  router.get('/v1/authorizations/:authorizationId/bank-transaction', async (req: AuthenticatedRequest, res, next) => {
    try {
      res.json(await getBankTransactionState(uuidSchema.parse(req.params.authorizationId), clientIdOf(req)));
    } catch (e) { next(e); }
  });

  return router;
}
