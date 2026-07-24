/**
 * Explainability Module
 * Computes exact contribution percentages for each risk signal based on log-odds math,
 * and formats the output into an ordered, analyst-friendly evidence array.
 */

/**
 * Generates an explainable evidence chain where contribution percentages sum to the final score.
 * 
 * Math justification:
 *   Let w_i = ln(LR_i) be the log-odds contribution of signal i.
 *   Only signals with w_i > 0 (LR_i > 1) contributed to increasing the risk.
 *   The relative contribution percentage is:
 *     contrib_i = (w_i / sum(w_k)) * finalScore
 * 
 * @param {object} params
 * @param {number} params.finalScore The final computed posterior confidence (0-100)
 * @param {object} params.details Object containing raw factors and their LRs
 * @param {number} params.details.receiverLR
 * @param {number} params.details.graphLR
 * @param {number} params.details.sequenceLR
 * @param {object} params.details.factors Raw values for descriptions
 * @returns {Array<object>} Ordered array of evidence logs
 */
export function buildEvidenceChain(finalScore, { receiverLR, graphLR, sequenceLR, factors = {} }) {
  const evidence = [];

  // 1. Calculate log-odds weight (ln(LR)) for each component
  const wReceiver = Math.max(0, Math.log(receiverLR || 1.0));
  const wGraph = Math.max(0, Math.log(graphLR || 1.0));
  const wSequence = Math.max(0, Math.log(sequenceLR || 1.0));

  const totalWeight = wReceiver + wGraph + wSequence;

  // Raw signal list
  const signals = [
    {
      key: 'receiver_posture',
      weight: wReceiver,
      lr: receiverLR,
      description: `Receiver posture score is elevated (Hawkes intensity: ${factors.hawkesIntensity?.toFixed(2) || '0.00'}, fund pass-through half-life: ${factors.halfLife ? factors.halfLife + 's' : 'N/A'}).`
    },
    {
      key: 'graph_reputation',
      weight: wGraph,
      lr: graphLR,
      description: `Graph reputation analysis identified proximity to reported fraud clusters (PageRank: ${factors.pageRank?.toFixed(6) || '0.000000'}${factors.inSuspiciousCommunity ? ', in Louvain community: ' + factors.communityId : ''}).`
    },
    {
      key: 'sequence_matching',
      weight: wSequence,
      lr: sequenceLR,
      description: `Sender session sequence displays strong alignment with known cashout timelines (subsequence match: ${(factors.sequenceMatchRatio * 100 || 0).toFixed(0)}%).`
    }
  ];

  if (totalWeight > 0 && finalScore > 0) {
    // Distribute the finalScore proportionally across signals with weight > 0
    let distributedSum = 0;
    const activeSignals = signals.filter(s => s.weight > 0);

    activeSignals.forEach((s, idx) => {
      // For the last element, assign the remainder to prevent rounding mismatch
      if (idx === activeSignals.length - 1) {
        s.contributionPct = finalScore - distributedSum;
      } else {
        s.contributionPct = Math.round((s.weight / totalWeight) * finalScore);
        distributedSum += s.contributionPct;
      }
    });

    // Populate evidence array with only contributing signals
    signals.forEach(s => {
      if (s.contributionPct && s.contributionPct > 0) {
        evidence.push({
          signal: s.key,
          contributionPct: s.contributionPct,
          description: s.description
        });
      }
    });
  }

  // If no signals contributed or final score is 0, return a baseline explanation
  if (evidence.length === 0) {
    evidence.push({
      signal: 'baseline_prior',
      contributionPct: finalScore || 2,
      description: 'Account profile features represent standard baseline behaviors.'
    });
  }

  // Sort by contribution percentage descending
  return evidence.sort((a, b) => b.contributionPct - a.contributionPct);
}
