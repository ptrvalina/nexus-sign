// Commission by the bank's policy (config/bank.json), integer minor units.
export function commission(policy, kind, amountMinor) {
  const rule = policy.fees[kind];
  if (!rule) throw new Error(`no fee rule for ${kind}`);
  const percent = Math.floor((amountMinor * rule.percentBasisPoints) / 10_000);
  return Math.min(Math.max(percent, rule.minMinor), rule.maxMinor);
}

export function formatMinor(minor, currency) {
  const sign = minor < 0 ? '-' : '';
  const abs = Math.abs(minor);
  return `${sign}${Math.floor(abs / 100)}.${String(abs % 100).padStart(2, '0')} ${currency}`;
}
