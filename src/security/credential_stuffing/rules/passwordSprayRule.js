/**
 * Rule R6: Password Spraying Detection
 * Detects password spraying attacks where the same password hash is attempted across many user accounts.
 */

export function checkPasswordSpray(passwordHashState = {}, passwordHash = null) {
  if (!passwordHash || typeof passwordHash !== 'string' || passwordHash.trim() === '') {
    return {
      score_contribution: 0.0,
      reason: null,
      evidence: {}
    };
  }

  const distinctUsersSet = passwordHashState.distinct_users_set || new Set();
  const distinctUserCount = distinctUsersSet.size;

  if (distinctUserCount >= 5) {
    const prefix = passwordHash.length >= 8 ? passwordHash.substring(0, 8) : passwordHash;
    const reason = `Password spraying: same password hash attempted across ${distinctUserCount} distinct accounts in the last 10 minutes`;
    const evidence = {
      rule: 'password_spray',
      password_hash_prefix: prefix,
      distinct_user_count: distinctUserCount,
      confidence: 'high'
    };

    return {
      score_contribution: 70.0,
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
