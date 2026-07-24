/**
 * Rule R3: Failure Ratio Anomaly Detection
 * Checks whether an IP address has an abnormally high login failure rate (>80%),
 * suggesting automated credential testing.
 */

export function checkFailureRatio(ipState = {}, ipAddress = '') {
  const failedCount = ipState.failed_count || 0;
  const successCount = ipState.success_count || 0;
  const totalAttempts = failedCount + successCount;

  // Total attempts < 5 -> not enough data
  if (totalAttempts < 5) {
    return {
      score_contribution: 0.0,
      reason: null,
      evidence: {}
    };
  }

  const failureRatio = failedCount / totalAttempts;

  if (failureRatio > 0.80) {
    const failurePercentage = Math.round(failureRatio * 1000) / 10;
    const reason = `Automated failure pattern: ${failurePercentage}% failure rate from IP ${ipAddress} (${failedCount} failed out of ${totalAttempts} attempts)`;
    const evidence = {
      rule: 'failure_ratio',
      ip_address: ipAddress,
      failure_ratio: Math.round(failureRatio * 1000) / 1000,
      total_attempts: totalAttempts,
      failed_count: failedCount,
      success_count: successCount,
      confidence: 'high'
    };

    return {
      score_contribution: 25.0,
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
