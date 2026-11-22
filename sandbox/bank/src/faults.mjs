// Fault injection for demonstration scenarios. It exists only in the sandbox
// bank and acts only on the sandbox's own traffic: the device port it proxies
// and the bank's copy of evidence it has received. Auth Core, the SDKs and
// their checks are untouched; a fault makes a check fail, it never makes one pass.
export function createFaults(enabled) {
  const state = { deviceNetworkDownUntil: 0, tamperEvidence: new Set(), suppressNotifications: new Set() };
  const guard = () => { if (!enabled) throw new Error('fault injection is disabled (SANDBOX_FAULT_INJECTION=enabled to allow it)'); };
  return {
    enabled,
    /** The device port answers 503 for this long, as if the phone lost its network. */
    dropDeviceNetwork(ms) { guard(); state.deviceNetworkDownUntil = Date.now() + ms; },
    deviceNetworkDown: () => enabled && Date.now() < state.deviceNetworkDownUntil,
    /** The bank's received copy of this transaction's evidence is altered before the bank checks it. */
    tamperEvidenceOf(transactionId) { guard(); state.tamperEvidence.add(transactionId); },
    takeEvidenceTamper(transactionId) { return enabled && state.tamperEvidence.delete(transactionId); },
    /** The bank's notification for this transaction is not delivered to the app. */
    suppressNotificationOf(transactionId) { guard(); state.suppressNotifications.add(transactionId); },
    notificationSuppressed: (transactionId) => enabled && state.suppressNotifications.has(transactionId),
  };
}
