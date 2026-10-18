// How the demo bank presents an authorization from GET /v1/authorizations/{id}.
// A payment counts as confirmed only when Auth Core reports VERIFIED and
// confirmed: true. OFFLINE_PROVISIONAL (an offline code without the device's
// signature yet) is never shown or treated as confirmed (FI-004).
const LABELS = {
  PENDING_USER: 'ждёт клиента',
  VERIFIED: 'подтверждён подписью устройства',
  OFFLINE_PROVISIONAL: 'код принят, ждём подпись телефона — не исполнять',
  OFFLINE_UNSIGNED: 'код принят, подпись не пришла — инцидент безопасности',
  REJECTED: 'отклонён',
  EXPIRED: 'истёк',
  CANCELLED: 'отменён',
};

/** { label, confirmed, css } for one authorization view (or an HTTP error). */
export function paymentStatus(view, httpStatus = 200) {
  if (httpStatus !== 200 || !view || typeof view.state !== 'string') {
    return { label: `нет ответа Auth Core (HTTP ${httpStatus})`, confirmed: false, css: 'bad' };
  }
  const confirmed = view.state === 'VERIFIED' && view.confirmed === true;
  const css = confirmed ? 'ok' : ['PENDING_USER', 'OFFLINE_PROVISIONAL'].includes(view.state) ? 'wait' : 'bad';
  return { label: LABELS[view.state] ?? `неизвестное состояние ${view.state}`, confirmed, css };
}
