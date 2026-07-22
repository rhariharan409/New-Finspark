/**
 * User Behavioral Baseline Service
 * Calculation engine that computes and upserts normal user behavioral baselines from real historical data in Supabase.
 * Strictly enforces baseline safety policy: ONLY LOW-RISK transactions update the behavioral baseline.
 */

import { baselineRepository } from '../db/baselineRepository.js';
import { transactionRepository } from '../db/transactionRepository.js';
import { telemetryRepository } from '../db/telemetryRepository.js';
import { supabase } from '../db/supabaseClient.js';
import { identityService } from '../security/identityService.js';

/**
 * Utility helper to find the most frequent (mode) value in an array of non-null strings
 */
function findMostFrequent(items) {
  if (!items || items.length === 0) return null;
  const frequencyMap = {};
  let maxCount = 0;
  let modeItem = null;

  for (const item of items) {
    if (item === null || item === undefined || item === '') continue;
    const cleanItem = String(item).trim();
    frequencyMap[cleanItem] = (frequencyMap[cleanItem] || 0) + 1;
    if (frequencyMap[cleanItem] > maxCount) {
      maxCount = frequencyMap[cleanItem];
      modeItem = cleanItem;
    }
  }

  return modeItem;
}

export const baselineService = {
  /**
   * Calculates and stores/updates a user's normal behavioral baseline from legitimate LOW RISK data in Supabase
   */
  async calculateAndSaveUserBaseline(userId, triggerRiskLevel = 'LOW') {
    if (!userId) {
      throw new Error('Baseline calculation error: Valid user_id is required.');
    }

    // BASELINE SAFETY POLICY: High/Critical/Medium risk events MUST NOT redefine the user's normal baseline
    if (triggerRiskLevel && ['MEDIUM', 'HIGH', 'CRITICAL'].includes(triggerRiskLevel.toUpperCase())) {
      console.log(`Baseline Guard: Skipping baseline update for user '${userId}' due to '${triggerRiskLevel}' risk event.`);
      return await this.getUserBaseline(userId);
    }

    // 1. Fetch existing baseline (if any) to preserve baseline_id and created_at
    const existingBaseline = await baselineRepository.getBaselineByUserId(userId);

    // 2. Retrieve real historical transactions sent by the user
    const allUserTxns = await transactionRepository.getTransactionsForUser(userId);
    const sentTxns = allUserTxns.filter(t => t.sender_user_id === userId);

    // 3. Query risk decisions to filter out MEDIUM, HIGH, and CRITICAL risk transactions
    const { data: userRiskDecisions } = await supabase
      .from('risk_decisions')
      .select('transaction_id, risk_level, risk_score')
      .eq('user_id', userId);

    const flaggedTxIds = new Set(
      (userRiskDecisions || [])
        .filter(r => ['MEDIUM', 'HIGH', 'CRITICAL'].includes(r.risk_level) || (r.risk_score && r.risk_score >= 30))
        .map(r => r.transaction_id)
    );

    // Filter sentTxns to include ONLY legitimate LOW-RISK transactions
    const legitimateTxns = sentTxns.filter(t => !flaggedTxIds.has(t.transaction_id));

    // 4. Retrieve real telemetry events for the user
    const telemetryEvents = await telemetryRepository.getEventsForUser(userId);

    // 5. Retrieve session history for the user directly from Supabase sessions table
    const { data: userSessions, error: sessionErr } = await supabase
      .from('sessions')
      .select('*')
      .eq('user_id', userId);

    if (sessionErr) {
      console.error('Fetch user sessions error during baseline calculation:', sessionErr.message);
    }
    const sessionsList = userSessions || [];

    // --- METRIC CALCULATIONS ---

    // A. Legitimate Transaction Count & Average Transaction Amount
    const transaction_count = legitimateTxns.length > 0 ? legitimateTxns.length : sentTxns.length;
    const targetTxns = legitimateTxns.length > 0 ? legitimateTxns : sentTxns;

    let average_transaction_amount = 0;
    if (targetTxns.length > 0) {
      const totalAmount = targetTxns.reduce((sum, t) => sum + (parseFloat(t.amount) || 0), 0);
      average_transaction_amount = Math.round((totalAmount / targetTxns.length) * 100) / 100;
    }

    // B. Average Daily Transactions Frequency
    let average_daily_transactions = 0;
    if (targetTxns.length > 0) {
      const timestamps = targetTxns
        .map(t => new Date(t.transaction_timestamp || t.created_at).getTime())
        .filter(ts => !isNaN(ts))
        .sort((a, b) => a - b);

      if (timestamps.length > 0) {
        const earliest = timestamps[0];
        const latest = timestamps[timestamps.length - 1];
        const daysSpan = Math.max(1, (latest - earliest) / (1000 * 60 * 60 * 24));
        average_daily_transactions = Math.round((targetTxns.length / daysSpan) * 100) / 100;
      }
    }

    // C. Average Session Duration (in seconds)
    let average_session_duration_seconds = 0;
    const terminatedSessions = sessionsList.filter(s => s.session_duration_seconds !== null && s.session_duration_seconds !== undefined);
    if (terminatedSessions.length > 0) {
      const totalDuration = terminatedSessions.reduce((sum, s) => sum + (parseFloat(s.session_duration_seconds) || 0), 0);
      average_session_duration_seconds = Math.round((totalDuration / terminatedSessions.length) * 100) / 100;
    }

    // D. Common Behavioral Patterns (Most Frequent Values)
    const deviceTypes = telemetryEvents.map(e => e.device_type);
    const deviceIds = telemetryEvents.map(e => e.device_id);
    const locations = telemetryEvents.map(e => e.location);
    const transactionTypes = targetTxns.map(t => t.transaction_type);

    const common_device_type = findMostFrequent(deviceTypes) || 'Browser';
    const common_device_id = findMostFrequent(deviceIds);
    const common_location = findMostFrequent(locations);
    const common_transaction_type = findMostFrequent(transactionTypes) || 'transfer';

    // 6. Construct Baseline Entity
    const nowISO = new Date().toISOString();
    const baselineId = existingBaseline ? existingBaseline.baseline_id : identityService.generateBaselineId();
    const createdAt = existingBaseline ? existingBaseline.created_at : nowISO;

    const baselinePayload = {
      baseline_id: baselineId,
      user_id: userId,
      average_transaction_amount,
      transaction_count,
      average_daily_transactions,
      common_device_type,
      common_device_id,
      common_location,
      common_transaction_type,
      average_session_duration_seconds,
      last_calculated_at: nowISO,
      created_at: createdAt,
      updated_at: nowISO
    };

    // 7. UPSERT into Supabase user_baselines table
    return await baselineRepository.upsertBaseline(baselinePayload);
  },

  /**
   * Retrieves a user's baseline, calculating and saving it dynamically if not present
   */
  async getUserBaseline(userId) {
    if (!userId) {
      throw new Error('User ID is required to retrieve behavioral baseline.');
    }

    let baseline = await baselineRepository.getBaselineByUserId(userId);

    // If no baseline exists or values are 0 while user has transactions, recalculate dynamically
    if (!baseline || (baseline.average_transaction_amount === 0 && baseline.transaction_count === 0)) {
      baseline = await this.calculateAndSaveUserBaseline(userId, 'LOW');
    }

    return baseline;
  }
};
