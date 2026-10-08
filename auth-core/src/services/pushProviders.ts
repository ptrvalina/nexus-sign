import http2, { type ClientHttp2Session } from 'node:http2';
import { ApnsProviderToken } from '../crypto/apnsProviderToken';
import { forgetGoogleAccessToken, getGoogleAccessToken, parseServiceAccountJson, type GoogleServiceAccount } from '../crypto/googleServiceAccount';
import type { PushEnvelope } from './pushProtocol';

/**
 * Hands sealed push envelopes to Apple (APNs) and Google (FCM HTTP v1).
 *
 * Neither provider receives anything readable: the APNs alert carries the
 * bank's generic text (PUSH_ALERT_TITLE) and the app's notification service
 * extension replaces it after decrypting; FCM messages are data-only and the
 * app builds the notification itself. The message category is not sent either.
 */

export type PushProvider = 'APNS' | 'FCM';
export type ApnsEnvironment = 'PRODUCTION' | 'DEVELOPMENT';

export interface PushTarget {
  provider: PushProvider;
  deviceToken: string;
  apnsEnvironment: ApnsEnvironment | null;
}

export interface PushDispatch {
  messageId: string;
  envelope: PushEnvelope;
  expiresAt: Date;
  /** AUTHORIZATION_REQUEST messages replace an older request on the same device. */
  collapseId: string | null;
}

export type PushSendOutcome =
  /** Accepted by the provider (not yet seen by the device). */
  | { kind: 'sent'; providerMessageId: string | null; httpStatus: number }
  /** Temporary: try again later. */
  | { kind: 'retry'; error: string; httpStatus: number | null }
  /** The device token is no longer valid; the registration is retired. */
  | { kind: 'unregistered'; error: string; httpStatus: number }
  /** This message will never be accepted (too large, malformed). */
  | { kind: 'rejected'; error: string; httpStatus: number };

export interface PushSender {
  readonly provider: PushProvider;
  send(target: PushTarget, dispatch: PushDispatch): Promise<PushSendOutcome>;
  close(): void;
}

const REQUEST_TIMEOUT_MS = 10_000;

// --- APNs ---

export interface ApnsAlert { title: string; body: string }

export function apnsPayload(envelope: PushEnvelope, alert: ApnsAlert): string {
  return JSON.stringify({
    aps: {
      alert: alert.body ? { title: alert.title, body: alert.body } : { title: alert.title },
      // Lets the app's notification service extension decrypt and replace the text.
      'mutable-content': 1,
      sound: 'default',
    },
    nexus: envelope,
  });
}

/** Maps an APNs response (https://developer.apple.com/documentation/usernotifications/handling-notification-responses-from-apns). */
export function classifyApnsResponse(status: number, reason: string | null, apnsId: string | null): PushSendOutcome {
  if (status === 200) return { kind: 'sent', providerMessageId: apnsId, httpStatus: status };
  const error = `APNs ${status}${reason ? ` ${reason}` : ''}`;
  if (status === 410 || reason === 'BadDeviceToken' || reason === 'DeviceTokenNotForTopic' || reason === 'Unregistered') {
    return { kind: 'unregistered', error, httpStatus: status };
  }
  if (status === 429 || status >= 500 || reason === 'ExpiredProviderToken' || reason === 'InvalidProviderToken') {
    return { kind: 'retry', error, httpStatus: status };
  }
  return { kind: 'rejected', error, httpStatus: status };
}

const APNS_HOSTS: Record<ApnsEnvironment, string> = {
  PRODUCTION: 'https://api.push.apple.com',
  DEVELOPMENT: 'https://api.sandbox.push.apple.com',
};

export class ApnsSender implements PushSender {
  readonly provider = 'APNS' as const;
  private readonly token: ApnsProviderToken;
  private readonly sessions = new Map<ApnsEnvironment, ClientHttp2Session>();

  constructor(teamId: string, keyId: string, privateKeyPem: string, private readonly topic: string, private readonly alert: ApnsAlert) {
    this.token = new ApnsProviderToken(teamId, keyId, privateKeyPem);
  }

  /** One HTTP/2 connection per environment, reopened after an error or GOAWAY. */
  private session(environment: ApnsEnvironment): ClientHttp2Session {
    const existing = this.sessions.get(environment);
    if (existing && !existing.closed && !existing.destroyed) return existing;
    const session = http2.connect(APNS_HOSTS[environment]);
    const forget = () => { if (this.sessions.get(environment) === session) this.sessions.delete(environment); };
    session.on('error', forget);
    session.on('goaway', forget);
    session.on('close', forget);
    session.unref(); // an idle connection must not keep the process alive
    this.sessions.set(environment, session);
    return session;
  }

  send(target: PushTarget, dispatch: PushDispatch): Promise<PushSendOutcome> {
    if (!/^[0-9a-f]{64,200}$/i.test(target.deviceToken)) {
      return Promise.resolve({ kind: 'unregistered', error: 'APNs device token is malformed', httpStatus: 400 });
    }
    const body = apnsPayload(dispatch.envelope, this.alert);
    const headers: http2.OutgoingHttpHeaders = {
      ':method': 'POST',
      ':path': `/3/device/${target.deviceToken}`,
      authorization: `bearer ${this.token.get()}`,
      'apns-push-type': 'alert',
      'apns-priority': '10',
      'apns-topic': this.topic,
      'apns-id': dispatch.messageId,
      'apns-expiration': String(Math.floor(dispatch.expiresAt.getTime() / 1000)),
      'content-type': 'application/json',
      'content-length': Buffer.byteLength(body),
    };
    if (dispatch.collapseId) headers['apns-collapse-id'] = dispatch.collapseId;

    return new Promise((resolve) => {
      let settled = false;
      const finish = (outcome: PushSendOutcome) => { if (!settled) { settled = true; resolve(outcome); } };
      let request: http2.ClientHttp2Stream;
      try {
        request = this.session(target.apnsEnvironment ?? 'PRODUCTION').request(headers);
      } catch (error) {
        finish({ kind: 'retry', error: error instanceof Error ? error.message : 'APNs connection failed', httpStatus: null });
        return;
      }
      let status = 0;
      let apnsId: string | null = null;
      const chunks: Buffer[] = [];
      request.setTimeout(REQUEST_TIMEOUT_MS, () => {
        request.close(http2.constants.NGHTTP2_CANCEL);
        finish({ kind: 'retry', error: 'APNs request timed out', httpStatus: null });
      });
      request.on('response', (responseHeaders) => {
        status = Number(responseHeaders[':status'] ?? 0);
        const id = responseHeaders['apns-id'];
        apnsId = typeof id === 'string' ? id : null;
      });
      request.on('data', (chunk: Buffer) => { chunks.push(chunk); });
      request.on('end', () => {
        let reason: string | null = null;
        if (chunks.length > 0) {
          try { reason = (JSON.parse(Buffer.concat(chunks).toString('utf8')) as { reason?: string }).reason ?? null; } catch { reason = null; }
        }
        const outcome = classifyApnsResponse(status, reason, apnsId);
        if (reason === 'ExpiredProviderToken' || reason === 'InvalidProviderToken') this.token.reset();
        finish(outcome);
      });
      request.on('error', (error) => finish({ kind: 'retry', error: error.message, httpStatus: null }));
      request.end(body);
    });
  }

  close(): void {
    for (const session of this.sessions.values()) session.close();
    this.sessions.clear();
  }
}

// --- FCM ---

const FCM_SCOPE = 'https://www.googleapis.com/auth/firebase.messaging';

export function fcmMessage(target: PushTarget, dispatch: PushDispatch, nowMs: number = Date.now()): Record<string, unknown> {
  const ttlSeconds = Math.max(0, Math.floor((dispatch.expiresAt.getTime() - nowMs) / 1000));
  return {
    message: {
      token: target.deviceToken,
      // Data-only: the app decrypts and shows the notification itself.
      data: { nexus: JSON.stringify(dispatch.envelope) },
      android: {
        priority: 'HIGH',
        ttl: `${ttlSeconds}s`,
        ...(dispatch.collapseId ? { collapse_key: dispatch.collapseId } : {}),
      },
    },
  };
}

interface FcmErrorBody {
  error?: { status?: string; message?: string; details?: { '@type'?: string; errorCode?: string }[] };
}

/** Maps an FCM v1 response (https://firebase.google.com/docs/reference/fcm/rest/v1/ErrorCode). */
export function classifyFcmResponse(status: number, body: unknown): PushSendOutcome {
  if (status === 200) {
    const name = (body as { name?: unknown } | null)?.name;
    return { kind: 'sent', providerMessageId: typeof name === 'string' ? name : null, httpStatus: status };
  }
  const error = (body as FcmErrorBody | null)?.error;
  const errorCode = error?.details?.find((d) => typeof d.errorCode === 'string')?.errorCode ?? error?.status ?? null;
  const message = `FCM ${status}${errorCode ? ` ${errorCode}` : ''}`;
  if (errorCode === 'UNREGISTERED' || errorCode === 'SENDER_ID_MISMATCH' || status === 404) {
    return { kind: 'unregistered', error: message, httpStatus: status };
  }
  if (status === 401 || status === 429 || status >= 500 || errorCode === 'QUOTA_EXCEEDED' || errorCode === 'UNAVAILABLE' || errorCode === 'INTERNAL') {
    return { kind: 'retry', error: message, httpStatus: status };
  }
  return { kind: 'rejected', error: message, httpStatus: status };
}

export class FcmSender implements PushSender {
  readonly provider = 'FCM' as const;
  private readonly serviceAccount: GoogleServiceAccount;

  constructor(private readonly projectId: string, serviceAccountJson: string) {
    this.serviceAccount = parseServiceAccountJson(serviceAccountJson);
  }

  async send(target: PushTarget, dispatch: PushDispatch): Promise<PushSendOutcome> {
    let response: Response;
    try {
      const accessToken = await getGoogleAccessToken(this.serviceAccount, FCM_SCOPE);
      response = await fetch(`https://fcm.googleapis.com/v1/projects/${this.projectId}/messages:send`, {
        method: 'POST',
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
        headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(fcmMessage(target, dispatch)),
      });
    } catch (error) {
      return { kind: 'retry', error: error instanceof Error ? error.message : 'FCM request failed', httpStatus: null };
    }
    let body: unknown = null;
    try { body = await response.json(); } catch { body = null; }
    if (response.status === 401) forgetGoogleAccessToken(this.serviceAccount, FCM_SCOPE);
    return classifyFcmResponse(response.status, body);
  }

  close(): void {
    // fetch keeps no connection state of its own here.
  }
}
