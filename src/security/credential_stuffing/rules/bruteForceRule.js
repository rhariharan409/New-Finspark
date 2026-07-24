/**
 * Rule R2: Account Brute Force Detection
 * Checks whether a single user account is experiencing an abnormally high volume of login failures.
 */

export function checkBruteForce(userState = {}, entityId = '', baselineTracker = null) {
  const failedCount = userState.failed_count || 0;
  const sourceIpsSet = userState.source_ips_set || new Set();
  const sourceIpsCount = sourceIpsSet.size;

  let threshold = 5.0;
  let mean = 0.0;
  let stdDev = 0.0;

  if (baselineTracker) {
    const res = baselineTracker.getThreshold(entityId, 2.5, 5.0);
    threshold = res.threshold;
    mean = res.mean;
    stdDev = res.stdDev;
  }

  if (failedCount >= threshold) {
    const reason = `Account brute force: ${failedCount} failed login attempts for user '${entityId}' in the last 2 minutes from ${sourceIpsCount} distinct IP(s)`;
    const evidence = {
      rule: 'brute_force',
      entity_id: entityId,
      failed_count: failedCount,
      source_ips_count: sourceIpsCount,
      confidence: 'high',
      adaptive_threshold: Math.round(threshold * 100) / 100,
      baseline_mean: Math.round(mean * 100) / 100,
      baseline_std: Math.round(stdDev * 100) / 100
    };

    return {
      score_contribution: 45.0,
      reason,
      evidence
    };
  }

  return {
    score_contribution: 0.0,
    reason: null,
    evidence: {}
  };
}
