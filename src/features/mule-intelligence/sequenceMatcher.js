/**
 * Sequence Matcher
 * Detects whether a series of observed events matches known attack paths using Longest Common Subsequence (LCS).
 */

const KNOWN_CHAINS = [
  ['new_device_login', 'high_ato_risk', 'new_beneficiary', 'large_transfer'],
];

/**
 * Calculates the length of the Longest Common Subsequence (LCS) between two arrays.
 * @param {Array<string>} A 
 * @param {Array<string>} B 
 * @returns {number}
 */
function getLcsLength(A, B) {
  const m = A.length;
  const n = B.length;
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (A[i - 1] === B[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1] + 1;
      } else {
        dp[i][j] = Math.max(dp[i - 1][j], dp[i][j - 1]);
      }
    }
  }
  return dp[m][n];
}

/**
 * Normalizes and maps raw database telemetry/timeline events to canonical template symbols.
 * @param {Array<object>} observedEvents 
 * @returns {Array<string>}
 */
export function mapObservedEvents(observedEvents) {
  if (!Array.isArray(observedEvents)) return [];

  return observedEvents.map(evt => {
    if (!evt) return null;
    const type = String(evt.event_type || '').toLowerCase();
    const desc = String(evt.description || '').toLowerCase();
    const metadata = evt.metadata || {};

    // 1. Map 'new_device_login'
    if (type === 'login' && (metadata.is_new_device || metadata.device_changed)) {
      return 'new_device_login';
    }
    if (type === 'session created' && desc.includes('new device')) {
      return 'new_device_login';
    }
    if (desc.includes('unrecognized device') || desc.includes('device mismatch')) {
      return 'new_device_login';
    }

    // 2. Map 'high_ato_risk'
    if (type === 'risk increased' || type === 'ato alert created' || type === 'ato_alert') {
      return 'high_ato_risk';
    }
    if (evt.risk_score && evt.risk_score >= 50) {
      return 'high_ato_risk';
    }
    if (desc.includes('critical risk') || desc.includes('high risk')) {
      return 'high_ato_risk';
    }

    // 3. Map 'new_beneficiary'
    if (type === 'new_receiver' || type === 'new_beneficiary') {
      return 'new_beneficiary';
    }
    if (type === 'transaction executed' && (desc.includes('to account') || desc.includes('recipient'))) {
      // In the baseline/risk repo, new receivers add a low baseline score (+5)
      return 'new_beneficiary';
    }

    // 4. Map 'large_transfer'
    if (type === 'transaction_created' && (parseFloat(metadata.amount) > 50000 || parseFloat(evt.amount) > 50000)) {
      return 'large_transfer';
    }
    if (type === 'transaction executed' && desc.includes('₹')) {
      const parts = desc.split('₹');
      if (parts.length > 1) {
        const amt = parseFloat(parts[1].replace(/,/g, ''));
        if (amt > 50000) {
          return 'large_transfer';
        }
      }
    }
    if (parseFloat(evt.amount) > 50000) {
      return 'large_transfer';
    }

    return null;
  }).filter(Boolean);
}

/**
 * Scores an observed event sequence against known attack-chain templates.
 * Returns the best match ratio (0.0 to 1.0).
 * @param {Array<object>} observedEvents 
 * @returns {number}
 */
export function scoreSequence(observedEvents) {
  const mapped = mapObservedEvents(observedEvents);
  if (mapped.length === 0) return 0;

  let maxRatio = 0;
  for (const chain of KNOWN_CHAINS) {
    const lcs = getLcsLength(chain, mapped);
    const ratio = lcs / chain.length;
    if (ratio > maxRatio) {
      maxRatio = ratio;
    }
  }

  return maxRatio;
}
