'use strict';

// Call code (finding A2-11): six digits from the DTLS certificate
// fingerprints of the phone's offer and the operator's answer. The phone
// shows the same code. Auth Core relays the session descriptions; if anyone
// in that path substitutes a fingerprint to sit in the middle of the media,
// the two codes differ. The operator reads the code out and the customer
// compares it with the app. Vectors: auth-core/test-vectors/call-code-v1.json.

/** "<hash> <HEX>" from the first a=fingerprint line, or null. */
function sdpFingerprint(sdp) {
  for (const raw of String(sdp ?? '').split(/\r\n|\r|\n/)) {
    const m = /^a=fingerprint:(\S+) ([0-9A-Fa-f:]+)\s*$/i.exec(raw.trim());
    if (m) return `${m[1].toLowerCase()} ${m[2].toUpperCase()}`;
  }
  return null;
}

/** The six-digit call code, or null when either side has no fingerprint. */
async function callCode(offerSdp, answerSdp) {
  const offer = sdpFingerprint(offerSdp);
  const answer = sdpFingerprint(answerSdp);
  if (!offer || !answer) return null;
  const text = new TextEncoder();
  const parts = [text.encode('NEXUS-SIGN/CALL-CODE/v1'), new Uint8Array([0]), text.encode(offer), new Uint8Array([0]), text.encode(answer)];
  const input = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) { input.set(p, at); at += p.length; }
  const digest = new DataView(await crypto.subtle.digest('SHA-256', input));
  return String(digest.getUint32(0) % 1000000).padStart(6, '0');
}
