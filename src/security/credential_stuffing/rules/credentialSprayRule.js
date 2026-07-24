/**
 * Rule R1: Credential Spraying Detection (IP Level)
 * Detects credential spraying where one IP address targets many distinct user accounts.
 * Requires corroboration (Gate 1: failure ratio, Gate 2: velocity, Gate 3: wide spray pattern)
 * to suppress false positives in NAT / shared IP environments.
 */

export function checkCredentialSpray(
  ipState = {},
  ipAddress = '',
  failureRatioFired = false,
  velocitySpikeFired = false,
  baselineTracker = null
) {
  const targetUsersSet = ipState.target_users_set || new Set();
  const distinctUserCount = targetUsersSet.size;

  let threshold = 3.0;
  let mean = 0.0;
  let stdDev = 0.0;

  if (baselineTracker) {
    const res = baselineTracker.getThreshold(ipAddress, 2.5, 3.0);
    threshold = res.threshold;
    mean = res.mean;
    stdDev = res.stdDev;
  }

  // 1. Less than 3 distinct users -> not enough spread
  if (distinctUserCount < 3) {
    return {
      score_contribution: 0.0,
      reason: null,
      evidence: {}
    };
  }

  // 2. Check corroboration gates for distinctUserCount >= 3
  let whichGate = null;
  const gate3Threshold = Math.max(8, Math.floor(threshold));

  if (failureRatioFired) {
    whichGate = 'high failure ratio';
  } else if (velocitySpikeFired) {
    whichGate = 'velocity anomaly';
  } else if (distinctUserCount >= gate3Threshold) {
    whichGate = `wide spray pattern (≥${gate3Threshold} users)`;
  }

  // If one of the gates passed -> FIRE
  if (whichGate !== null) {
    const reason = `Credential spray: IP ${ipAddress} targeted ${distinctUserCount} distinct accounts in the last 5 minutes [corroborated by ${whichGate}]`;
    const evidence = {
      rule: 'credential_spray',
      ip_address: ipAddress,
      distinct_user_count: distinctUserCount,
      corroboration_gate: whichGate,
      confidence: 'medium-high',
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

  // If no gate passed -> SUPPRESS due to possible NAT / shared IP
  return {
    score_contribution: 0.0,
    reason: null,
    evidence: {
      rule: 'credential_spray_suppressed_nat',
      ip_address: ipAddress,
      distinct_user_count: distinctUserCount,
      note: 'Suppressed due to possible NAT/shared IP — no corroborating signal',
      adaptive_threshold: Math.round(threshold * 100) / 100,
      baseline_mean: Math.round(mean * 100) / 100,
      baseline_std: Math.round(stdDev * 100) / 100
    }
  };
}
