/**
 * The reason a state change in this transaction is recorded with in
 * evidence_outcomes (migration 025). The database trigger reads it from the
 * transaction-local setting `nexus.outcome_reason`, and uses a default per
 * state when it is not set. Set it immediately before the UPDATE it explains.
 */
export async function setOutcomeReason(tx: { query: (sql: string, args?: unknown[]) => Promise<unknown> }, reason: string): Promise<void> {
  await tx.query(`SELECT set_config('nexus.outcome_reason', $1, true)`, [reason.slice(0, 64)]);
}
