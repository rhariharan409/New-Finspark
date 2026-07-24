/**
 * Bayesian Fusion Engine
 * Fuses independent risk signal Likelihood Ratios (LR) with a prior probability
 * to compute a final Money Mule Confidence Score (0-100%).
 */

// Configuration constants
export const CONFIG = {
  BASE_PRIOR: 0.02, // Configurable prior probability (2% base probability of any account being a mule)
};

/**
 * Fuses Likelihood Ratios (LRs) using sequential Bayes' theorem in odds form.
 * 
 * Formula justification:
 *   Odds(Mule | signals) = Odds(Mule) * LR_receiver * LR_graph * LR_sequence
 *   Posterior = Odds / (1 + Odds)
 * 
 * Individual LR Justifications (detailed in comments below):
 * 
 * 1. Receiver LR (posture anomaly):
 *    - Measures frequency of incoming transfers (Hawkes intensity) and pass-through speed (half-life).
 *    - Formula: 1.0 + (8.0 / (1.0 + exp(-(hawkes - 3.0)))) + (6.0 / (1.0 + exp((halfLife - 180) / 60)))
 *    - If Hawkes intensity is high (many rapid inflows) and half-life is small (funds leave immediately), 
 *      the LR increases exponentially to flag structural velocity.
 * 
 * 2. Graph LR (network contamination):
 *    - Measures reputation contamination from PageRank and Louvain community metrics.
 *    - Formula: 1.0 + (graphReputation * 1500) + (isInSuspiciousCommunity ? 8.0 : 0.0)
 *    - Propagates higher likelihood if account is closely linked to reported fraud seeds or inside a Louvain ring.
 * 
 * 3. Sequence LR (attack timeline chain alignment):
 *    - Measures alignment with chronological session takeover and cashout sequences.
 *    - Formula: 1.0 + (12.0 / (1.0 + exp(-8.0 * (matchRatio - 0.5))))
 *    - If the sequence match ratio exceeds 50%, the LR jumps significantly to signal an active attack-chain execution.
 * 
 * @param {object} params
 * @param {number} [params.basePrior] Prior probability (defaults to CONFIG.BASE_PRIOR)
 * @param {number} params.receiverLR Likelihood Ratio for receiver posture
 * @param {number} params.graphLR Likelihood Ratio for graph network reputation
 * @param {number} params.sequenceLR Likelihood Ratio for attack-timeline sequence
 * @returns {number} Final confidence score as an integer percentage (0-100)
 */
export function fuseMuleConfidence({ 
  basePrior = CONFIG.BASE_PRIOR, 
  receiverLR, 
  graphLR, 
  sequenceLR 
}) {
  // Guard against basePrior producing odds of exactly 0 or 1
  const cleanPrior = Math.max(0.0001, Math.min(0.9999, basePrior));

  const odds = (p) => p / (1 - p);
  let o = odds(cleanPrior);

  // Apply LRs sequentially (using 1.0 as identity if undefined or invalid)
  o *= (receiverLR !== undefined && receiverLR >= 0) ? receiverLR : 1.0;
  o *= (graphLR !== undefined && graphLR >= 0) ? graphLR : 1.0;
  o *= (sequenceLR !== undefined && sequenceLR >= 0) ? sequenceLR : 1.0;

  const posterior = o / (1 + o);

  return Math.min(100, Math.max(0, Math.round(posterior * 100)));
}
