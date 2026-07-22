/**
 * Risk Decision Data Model
 * Defines risk levels, decisions, and entity formatting for Bank of Turtles.
 */

export const RISK_LEVEL = Object.freeze({
  LOW: 'LOW',
  MEDIUM: 'MEDIUM',
  HIGH: 'HIGH',
  CRITICAL: 'CRITICAL'
});

export const RISK_DECISION = Object.freeze({
  ALLOW: 'ALLOW',
  REVIEW: 'REVIEW',
  BLOCK: 'BLOCK'
});

/**
 * Maps a calculated risk score (0-100) to corresponding risk level and decision
 */
export function classifyRiskScore(score) {
  const numScore = Math.max(0, Math.min(100, parseFloat(score) || 0));

  if (numScore < 30) {
    return { risk_level: RISK_LEVEL.LOW, decision: RISK_DECISION.ALLOW };
  }
  if (numScore < 60) {
    return { risk_level: RISK_LEVEL.MEDIUM, decision: RISK_DECISION.ALLOW };
  }
  if (numScore < 80) {
    return { risk_level: RISK_LEVEL.HIGH, decision: RISK_DECISION.REVIEW };
  }
  return { risk_level: RISK_LEVEL.CRITICAL, decision: RISK_DECISION.BLOCK };
}

/**
 * Creates a formatted Risk Decision entity adhering to system standards
 */
export function createRiskDecisionEntity({
  risk_decision_id,
  transaction_id,
  user_id,
  risk_score,
  risk_level,
  decision,
  risk_factors,
  baseline_snapshot,
  created_at
}) {
  const score = Math.max(0, Math.min(100, parseFloat(risk_score) || 0));
  const classification = classifyRiskScore(score);

  return {
    risk_decision_id: risk_decision_id || '',
    transaction_id: transaction_id || '',
    user_id: user_id || '',
    risk_score: score,
    risk_level: risk_level || classification.risk_level,
    decision: decision || classification.decision,
    risk_factors: risk_factors && typeof risk_factors === 'object' ? risk_factors : {},
    baseline_snapshot: baseline_snapshot && typeof baseline_snapshot === 'object' ? baseline_snapshot : {},
    created_at: created_at || new Date().toISOString()
  };
}
