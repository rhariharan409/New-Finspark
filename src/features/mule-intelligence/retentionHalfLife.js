/**
 * Retention Half-Life Engine
 * Computes seconds until 50% of an inflow amount has left the account.
 */

/**
 * Calculates retention half-life in seconds.
 * @param {number} inflowAmount The amount of the incoming transfer
 * @param {number} inflowTimestampMs The timestamp of the incoming transfer in milliseconds
 * @param {Array<{amount: number, timestampMs: number}>} outflowEvents Array of outflows after the inflow timestamp
 * @returns {number|null} Half-life in seconds, or null if 50% outflow threshold not reached
 */
export function computeHalfLife(inflowAmount, inflowTimestampMs, outflowEvents) {
  if (!outflowEvents || outflowEvents.length === 0) {
    return null;
  }

  // Ensure outflowEvents are sorted chronologically without mutating caller array
  const sortedOutflows = [...outflowEvents].sort((a, b) => (a.timestampMs || 0) - (b.timestampMs || 0));

  // Ensure target is exactly 50% of inflow amount
  const target = inflowAmount / 2;
  let cumulative = 0;

  for (const ev of sortedOutflows) {
    cumulative += ev.amount;
    if (cumulative >= target) {
      return (ev.timestampMs - inflowTimestampMs) / 1000;
    }
  }

  return null; // half-life not yet reached
}
