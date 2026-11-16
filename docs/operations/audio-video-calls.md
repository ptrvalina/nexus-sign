# Audio and video verification calls: deployment and operation

Architecture and decisions: [ADR 0017](../adr/0017-in-app-audio-video-calls.md). Result tokens of external providers: [verification result v1](../protocol/verification-result-v1.md).

## Components

| Component | Who runs it | Purpose |
|---|---|---|
| Auth Core | Bank | Session control, signalling relay, TURN credentials, results, evidence |
| Redis | Bank | Signalling messages and call claims, for the life of a session (at most about 6 minutes) |
| TURN/STUN (coturn) | Bank, reachable from the internet | NAT traversal; relays encrypted media when no direct path exists |
| Admin console | Bank operators, browser | Answers calls, shows the transaction terms, records the result |
| Bank app with NEXUS-SIGN SDK and its call module | Customer | Joins the call, shows camera and microphone state ([Android](../../android-sdk-calls/README.md), [iOS](../../ios-sdk-calls/README.md)) |
| External verification provider (optional) | Third party | Holds calls or automated checks; signs result tokens |

No media passes through Auth Core. Nothing is recorded.

## Configuration

### Auth Core

| Variable | Example | Notes |
|---|---|---|
| `WEBRTC_STUN_URLS` | `stun:turn.bank.example:3478` | Comma-separated |
| `WEBRTC_TURN_URLS` | `turn:turn.bank.example:3478?transport=udp,turns:turn.bank.example:5349?transport=tcp` | Offer TLS on 5349 for networks that allow only TCP 443/5349 |
| `WEBRTC_TURN_SECRET` | from the secrets manager | coturn `static-auth-secret`, at least 16 characters |
| `WEBRTC_TURN_CREDENTIAL_TTL_SECONDS` | `600` | Upper bound; credentials also expire with the session |

### Which channels a bank verifies, and how

```bash
node dist/cli/verificationSetup.js operator <clientId> AUDIO,VIDEO     # operators answer in the admin console
node dist/cli/verificationSetup.js provider-add <clientId> <providerId> <keyId> VIDEO provider.pub.pem
node dist/cli/verificationSetup.js show <clientId>
```

A channel with neither is not offered in verification plans.

### Operator accounts

Operators are admin accounts with role `operator` scoped to the bank (`createAdminUser.js <name> operator --client=<clientId>`), with TOTP. They see and answer only that bank's calls. A call is claimed by one operator (`verification_call_claimed` in the audit log). The decision is recorded with the operator's username in the evidence.

### coturn (reference)

```
listening-port=3478
tls-listening-port=5349
fingerprint
use-auth-secret
static-auth-secret=<WEBRTC_TURN_SECRET>
realm=turn.bank.example
cert=/etc/coturn/tls/fullchain.pem
pkey=/etc/coturn/tls/privkey.pem
no-cli
no-tcp-relay
denied-peer-ip=10.0.0.0-10.255.255.255
denied-peer-ip=172.16.0.0-172.31.255.255
denied-peer-ip=192.168.0.0-192.168.255.255
total-quota=200
stale-nonce=600
```

The `denied-peer-ip` lines keep the relay from reaching internal networks. Add the bank's own ranges. Open UDP 3478, TCP/TLS 5349 and the relay port range (`min-port`/`max-port`) on the firewall.

### Security boundaries

| Boundary | Protected by |
|---|---|
| Phone → Auth Core (signalling) | TLS (optionally pinned in the SDK), device request signature with one-time nonce, session bound to the authorization and credential |
| Operator browser → Auth Core | TLS, password + TOTP session, role `operator`, bank scope, one claim per call |
| Phone ↔ operator browser (media) | DTLS-SRTP negotiated by WebRTC; fingerprints exchanged through the authenticated signalling |
| Phone / browser → TURN | Per-session TURN REST credentials, valid until the session expires (at most `WEBRTC_TURN_CREDENTIAL_TTL_SECONDS`); TLS on 5349 |
| TURN → internal network | `denied-peer-ip` ranges, `no-tcp-relay`, quotas (below) |

The mobile apps contain no TURN secret; `WEBRTC_TURN_SECRET` stays in Auth Core and coturn.

### Logging

Request bodies are not logged by Auth Core (`req.body` is redacted), so SDP, ICE candidates (which contain IP addresses) and TURN credentials do not reach the logs. Audit events record claims, cancellations, expiries and decisions with session and authorization IDs only. Keep coturn at its default verbosity (`no-stdout-log` / `log-file` without `verbose`); verbose coturn logs contain peer addresses.

## Signalling rules

Auth Core refuses out-of-order signalling with 409 (an offer while one is unanswered, a candidate before its description, anything after the sender's bye) and wrong roles with 400 (an answer from the device, an offer from the operator). A repeated `messageId` returns 200 with the original `seq`. These rules are what the SDKs and the console follow; a client that gets 409 has a bug or a stale view of the call.

## Operation

| Situation | What happens | What to do |
|---|---|---|
| No operator answers within 5 minutes | Session `EXPIRED`, plan back to `PENDING`, audit `verification_session_expired` | Staff the queue; the customer may retry twice more, then the bank escalates or cancels |
| Customer declines | Session `CANCELLED`, plan `PENDING` | As above |
| Call drops | The phone restarts ICE (a new offer, answered by the console) after 4 s DISCONNECTED or on FAILED, at most twice; then the phone ends the call and cancels the session | The operator waits; after the end the customer may call again |
| Operator hangs up | `release`: session `CANCELLED` (audit `by: admin:<operator>`), plan `PENDING`, phone told `operator_left` | The customer may call again |
| Session closed elsewhere (authorization confirmed, rejected or expired, credential revoked) | Both parties receive a `bye` from `server` with the reason within about 2 s and stop capture | — |
| Operator records FAILED | Escalation to the next channel, or plan `FAILED` and authorization `REJECTED` | — |
| TURN unreachable | Calls fail to connect on restrictive networks | Monitor coturn; check `WEBRTC_TURN_URLS` |
| Auth Core restart during a call | Media continues peer to peer; signalling resumes from Redis | — |

Metrics to watch: the number of `IN_PROGRESS` sessions older than 2 minutes; the counts of `verification_session_expired`, `verification_session_cancelled` (by device and by operator) and `verification_result_rejected` audit events; 409 responses on `/signals` (client bugs); coturn allocation counts and relay bandwidth against `total-quota`.

## Data

| Data | Where | Retention |
|---|---|---|
| SDP and ICE candidates (contain IP addresses) | Redis | Session lifetime plus 60 s |
| Call claim (operator username) | Redis; audit log | Session lifetime; audit log retention |
| Result, method, issuer | `verification_sessions`, evidence | Evidence retention of the bank |
| Audio, video | Not stored | — |
