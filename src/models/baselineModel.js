/**
 * User Behavioral Baseline Data Model
 * Defines baseline schema attributes and entity formatting for Bank of Turtles.
 */

/**
 * Creates a formatted User Baseline entity adhering to system standards
 */
export function createBaselineEntity({
  baseline_id,
  user_id,
  average_transaction_amount,
  transaction_count,
  average_daily_transactions,
  common_device_type,
  common_device_id,
  common_location,
  common_transaction_type,
  average_session_duration_seconds,
  last_calculated_at,
  created_at,
  updated_at
}) {
  return {
    baseline_id: baseline_id || '',
    user_id: user_id || '',
    average_transaction_amount: parseFloat(average_transaction_amount) || 0,
    transaction_count: parseInt(transaction_count, 10) || 0,
    average_daily_transactions: parseFloat(average_daily_transactions) || 0,
    common_device_type: common_device_type || null,
    common_device_id: common_device_id || null,
    common_location: common_location || null,
    common_transaction_type: common_transaction_type || null,
    average_session_duration_seconds: parseFloat(average_session_duration_seconds) || 0,
    last_calculated_at: last_calculated_at || new Date().toISOString(),
    created_at: created_at || new Date().toISOString(),
    updated_at: updated_at || new Date().toISOString()
  };
}
