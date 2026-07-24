/**
 * Risk Analysis Engine Service
 * Analyzes transactions against user behavioral baselines and telemetry context to compute risk scores, factors, and decisions.
 */

import { riskRepository } from '../db/riskRepository.js';
import { transactionRepository } from '../db/transactionRepository.js';
import { telemetryRepository } from '../db/telemetryRepository.js';
import { baselineService } from './baselineService.js';
import { transactionService } from './transactionService.js';
import { identityService } from '../security/identityService.js';
import { classifyRiskScore } from '../models/riskModel.js';
import { supabase } from '../db/supabaseClient.js';

/**
 * Helper to parse User-Agent / device_type string into Operating System and Browser
 */
function parseUserAgent(deviceTypeStr) {
  if (!deviceTypeStr || typeof deviceTypeStr !== 'string') {
    return { browser: 'Unknown Browser', operating_system: 'Unknown OS' };
  }
  const ua = deviceTypeStr.toLowerCase();

  let os = 'Unknown OS';
  if (ua.includes('win')) os = 'Windows';
  else if (ua.includes('mac')) os = 'macOS';
  else if (ua.includes('android')) os = 'Android';
  else if (ua.includes('iphone') || ua.includes('ipad') || ua.includes('ios')) os = 'iOS';
  else if (ua.includes('linux')) os = 'Linux';

  let browser = 'Unknown Browser';
  if (ua.includes('edg')) browser = 'Edge';
  else if (ua.includes('chrome') || ua.includes('crios')) browser = 'Chrome';
  else if (ua.includes('firefox') || ua.includes('fxios')) browser = 'Firefox';
  else if (ua.includes('safari') && !ua.includes('chrome')) browser = 'Safari';
  else if (ua.includes('opera') || ua.includes('opr')) browser = 'Opera';
  else if (ua.includes('node') || ua.includes('postman')) browser = 'API Client';
  else if (deviceTypeStr.length > 0) browser = deviceTypeStr.length > 30 ? deviceTypeStr.substring(0, 30) : deviceTypeStr;

  return { browser, operating_system: os };
}

export const riskAnalysisService = {
  /**
   * Analyzes a transaction against the user's historical behavioral baseline and telemetry context to compute risk score, advanced behavioral signals, and decisions.
   */
  async analyzeTransactionRisk({ transactionId, userId, sessionRiskContext }) {
    if (!transactionId || !userId) {
      throw new Error('Risk Analysis Error: Both transaction_id and user_id are required.');
    }

    // 1. Retrieve Target Transaction
    const transaction = await transactionRepository.getTransactionById(transactionId);
    if (!transaction) {
      throw new Error(`Risk Analysis Error: Transaction '${transactionId}' not found.`);
    }

    // 2. Security Guard: Verify Transaction Owner
    if (transaction.sender_user_id !== userId) {
      throw new Error('Unauthorized Risk Analysis: You can only analyze your own transactions.');
    }

    // 3. Check if a Risk Decision already exists for this transaction_id
    const existingDecision = await riskRepository.getRiskDecisionByTransactionId(transactionId);
    if (existingDecision) {
      return existingDecision;
    }

    // 4. Retrieve User's Behavioral Baseline (calculates dynamically if missing)
    const baseline = await baselineService.getUserBaseline(userId);

    // 5. Retrieve User's Telemetry, Transaction, and Session History
    const userTelemetry = await telemetryRepository.getEventsForUser(userId);
    const userTxns = await transactionRepository.getTransactionsForUser(userId);
    const sentTxns = userTxns.filter(t => t.sender_user_id === userId);
    const previousSentTxns = sentTxns.filter(t => t.transaction_id !== transactionId);

    const latestTelemetry = userTelemetry.length > 0 ? userTelemetry[0] : null;

    const { data: userSessions } = await supabase
      .from('sessions')
      .select('*')
      .eq('user_id', userId)
      .order('login_time', { ascending: false });
    const sessionsList = userSessions || [];

    const risk_factors = {};
    let totalScore = 0;

    // CORRELATION: Factor in session-level accumulated risk
    if (sessionRiskContext && sessionRiskContext.combinedScore > 0) {
      const sessionCarryover = Math.min(sessionRiskContext.combinedScore * 0.5, 30);
      totalScore += sessionCarryover;
      risk_factors.session_risk_carryover = {
        score: sessionCarryover,
        severity: sessionCarryover >= 20 ? 'HIGH' : 'MEDIUM',
        explanation: `Session accumulated ${sessionRiskContext.combinedScore} risk points from pre-auth and session integrity checks.`,
        reason: `Inherited session risk.`
      };
    }

    // ==========================================
    // SIGNAL 1: AMOUNT DEVIATION
    // ==========================================
    const amount = parseFloat(transaction.amount) || 0;
    const avgAmount = parseFloat(baseline.average_transaction_amount) || 0;
    let amountScore = 0;
    let amountSeverity = 'LOW';
    let amountReason = 'Transaction amount is within normal historical range.';
    let deviationRatio = avgAmount > 0 ? Math.round((amount / avgAmount) * 10) / 10 : 1;

    if (baseline.transaction_count === 0 || avgAmount === 0) {
      amountScore = 10;
      amountSeverity = 'LOW';
      amountReason = 'Initial baseline - no prior transaction history for amount comparison.';
    } else if (amount > avgAmount) {
      const ratio = amount / avgAmount;
      deviationRatio = Math.round(ratio * 10) / 10;
      if (ratio > 5) {
        amountScore = 40;
        amountSeverity = 'CRITICAL';
        amountReason = `Transaction amount (₹${amount}) is ${deviationRatio}x higher than user average (₹${avgAmount}).`;
      } else if (ratio >= 2) {
        amountScore = 25;
        amountSeverity = 'HIGH';
        amountReason = `Transaction amount (₹${amount}) is significantly above user average (₹${avgAmount}).`;
      } else if (ratio >= 1.5) {
        amountScore = 15;
        amountSeverity = 'MEDIUM';
        amountReason = `Transaction amount (₹${amount}) is moderately above user average (₹${avgAmount}).`;
      }
    }

    risk_factors.amount_deviation = {
      amount,
      average_amount: avgAmount,
      deviation_ratio: deviationRatio,
      score: amountScore,
      severity: amountSeverity,
      explanation: amountReason,
      reason: amountReason
    };
    totalScore += amountScore;

    // ==========================================
    // SIGNAL 2: DEVICE INTELLIGENCE / DEVIATION
    // ==========================================
    const currentDeviceType = latestTelemetry?.device_type || 'browser';
    const currentDeviceId = latestTelemetry?.device_id || null;
    const { browser, operating_system } = parseUserAgent(currentDeviceType);

    const priorTelemetry = userTelemetry.filter(e => e.transaction_id !== transactionId);
    const knownDeviceIds = new Set(priorTelemetry.map(e => e.device_id).filter(Boolean));
    const knownDeviceTypes = new Set(priorTelemetry.map(e => e.device_type).filter(Boolean));
    if (baseline.common_device_id) knownDeviceIds.add(baseline.common_device_id);
    if (baseline.common_device_type) knownDeviceTypes.add(baseline.common_device_type);

    let isKnownDevice = true;
    let deviceScore = 0;
    let deviceSeverity = 'LOW';
    let deviceReason = `Recognized device (${browser} on ${operating_system}).`;

    if (priorTelemetry.length > 0) {
      const matchId = currentDeviceId && knownDeviceIds.has(currentDeviceId);
      const matchType = currentDeviceType && knownDeviceTypes.has(currentDeviceType);

      if (!matchId && !matchType) {
        isKnownDevice = false;
        deviceScore = 20;
        deviceSeverity = 'HIGH';
        deviceReason = `New or unrecognized device detected (${browser} on ${operating_system}).`;
      }
    }

    risk_factors.device_deviation = {
      current_device_id: currentDeviceId,
      known_device: isKnownDevice,
      device_type: currentDeviceType,
      operating_system,
      browser,
      score: deviceScore,
      severity: deviceSeverity,
      explanation: deviceReason,
      reason: deviceReason
    };
    totalScore += deviceScore;

    // ==========================================
    // SIGNAL 3: LOCATION DEVIATION
    // ==========================================
    const currentLocation = latestTelemetry?.location || null;
    const commonLocation = baseline.common_location || null;
    const knownLocations = new Set(priorTelemetry.map(e => e.location).filter(Boolean));
    if (commonLocation) knownLocations.add(commonLocation);

    let locationDeviation = 'NONE';
    let locationScore = 0;
    let locationSeverity = 'LOW';
    let locationReason = 'Current location matches user historical location patterns.';

    if (currentLocation && knownLocations.size > 0) {
      const isKnownLocation = Array.from(knownLocations).some(
        loc => loc.toLowerCase().trim() === currentLocation.toLowerCase().trim()
      );
      if (!isKnownLocation) {
        locationDeviation = 'HIGH';
        locationScore = 15;
        locationSeverity = 'HIGH';
        locationReason = `Unusual location detected (${currentLocation} vs common location ${commonLocation || 'unknown'}).`;
      }
    }

    risk_factors.location_deviation = {
      current_location: currentLocation,
      common_location: commonLocation,
      location_deviation: locationDeviation,
      score: locationScore,
      severity: locationSeverity,
      explanation: locationReason,
      reason: locationReason
    };
    totalScore += locationScore;

    // ==========================================
    // SIGNAL 4: TRANSACTION VELOCITY (Max +30)
    // ==========================================
    const txTimeMs = new Date(transaction.transaction_timestamp || transaction.created_at).getTime();
    const oneMinAgo = txTimeMs - 60 * 1000;
    const fiveMinAgo = txTimeMs - 5 * 60 * 1000;
    const fifteenMinAgo = txTimeMs - 15 * 60 * 1000;
    const oneHourAgo = txTimeMs - 60 * 60 * 1000;
    const twentyFourHoursAgo = txTimeMs - 24 * 60 * 60 * 1000;

    const recentSentTxns = sentTxns.filter(t => {
      const ts = new Date(t.transaction_timestamp || t.created_at).getTime();
      return !isNaN(ts) && ts <= txTimeMs;
    });

    const tx_1m = recentSentTxns.filter(t => new Date(t.transaction_timestamp || t.created_at).getTime() >= oneMinAgo).length;
    const tx_5m = recentSentTxns.filter(t => new Date(t.transaction_timestamp || t.created_at).getTime() >= fiveMinAgo).length;
    const tx_15m = recentSentTxns.filter(t => new Date(t.transaction_timestamp || t.created_at).getTime() >= fifteenMinAgo).length;
    const tx_1h = recentSentTxns.filter(t => new Date(t.transaction_timestamp || t.created_at).getTime() >= oneHourAgo).length;
    const tx_24h = recentSentTxns.filter(t => new Date(t.transaction_timestamp || t.created_at).getTime() >= twentyFourHoursAgo).length;

    const normalFrequency = parseFloat(baseline.average_daily_transactions) || 1;
    let velocityScore = 0;
    let velocitySeverity = 'LOW';
    let timeWindow = 'normal';
    let velocityReason = 'Transaction velocity is within normal historical limits.';

    if (tx_5m >= 5 || tx_15m >= 8 || tx_1m >= 4) {
      velocityScore = 30;
      velocitySeverity = 'CRITICAL';
      timeWindow = tx_1m >= 4 ? '1m' : (tx_5m >= 5 ? '5m' : '15m');
      velocityReason = `Excessive transaction velocity burst detected (${tx_5m} txns in 5m, ${tx_15m} txns in 15m).`;
    } else if (tx_5m >= 3 || tx_15m >= 5) {
      velocityScore = 20;
      velocitySeverity = 'HIGH';
      timeWindow = tx_5m >= 3 ? '5m' : '15m';
      velocityReason = `Elevated transaction velocity detected (${tx_5m} txns in 5m, ${tx_15m} txns in 15m).`;
    } else if (tx_15m >= 3 || tx_24h > Math.max(5, normalFrequency * 3)) {
      velocityScore = 10;
      velocitySeverity = 'MEDIUM';
      timeWindow = tx_15m >= 3 ? '15m' : '24h';
      velocityReason = `Moderate transaction velocity detected (${tx_15m} txns in 15m).`;
    }

    risk_factors.transaction_velocity = {
      recent_transaction_count: {
        last_1m: tx_1m,
        last_5m: tx_5m,
        last_15m: tx_15m,
        last_1h: tx_1h,
        last_24h: tx_24h
      },
      time_window: timeWindow,
      normal_transaction_frequency: normalFrequency,
      velocity_score: velocityScore,
      score: velocityScore,
      severity: velocitySeverity,
      explanation: velocityReason,
      reason: velocityReason
    };
    totalScore += velocityScore;

    // ==========================================
    // SIGNAL 4B: SPLIT TRANSACTION PATTERN DETECTION (Max +25)
    // ==========================================
    let splitScore = 0;
    let splitSeverity = 'LOW';
    let isSplitPattern = false;
    let splitReason = 'No split-transaction pattern detected.';
    let similarCountFound = 0;
    let sampleAmtFound = 0;

    const recent15mSentTxns = recentSentTxns.filter(t => new Date(t.transaction_timestamp || t.created_at).getTime() >= fifteenMinAgo);

    if (recent15mSentTxns.length >= 3) {
      const amounts = recent15mSentTxns.map(t => parseFloat(t.amount) || 0);

      for (const targetAmt of amounts) {
        if (targetAmt <= 0) continue;
        const similarCount = amounts.filter(a => Math.abs(a - targetAmt) / Math.max(a, targetAmt) <= 0.30).length;
        if (similarCount >= 3) {
          isSplitPattern = true;
          splitScore = 25;
          splitSeverity = 'CRITICAL';
          similarCountFound = similarCount;
          sampleAmtFound = targetAmt;
          splitReason = `Multiple similar-sized transactions (${similarCount} txns of ~₹${Math.round(targetAmt)}) detected within 15 minutes, indicating a potential split-transaction pattern.`;
          break;
        }
      }
    }

    risk_factors.split_transaction_pattern = {
      detected: isSplitPattern,
      similar_transaction_count: similarCountFound || recent15mSentTxns.length,
      sample_amount: sampleAmtFound,
      score: splitScore,
      severity: splitSeverity,
      explanation: splitReason,
      reason: splitReason
    };
    totalScore += splitScore;

    // ==========================================
    // SIGNAL 5: SESSION BEHAVIOR (Max +10)
    // ==========================================
    const currentSessionId = latestTelemetry?.session_id || null;
    const currentSession = currentSessionId ? sessionsList.find(s => s.session_id === currentSessionId) : sessionsList[0] || null;

    let sessionDurationSeconds = null;
    if (currentSession?.login_time) {
      const loginMs = new Date(currentSession.login_time).getTime();
      if (!isNaN(loginMs)) {
        sessionDurationSeconds = Math.max(0, Math.floor((txTimeMs - loginMs) / 1000));
      }
    }

    const sessionTelemetry = currentSessionId
      ? userTelemetry.filter(e => e.session_id === currentSessionId)
      : userTelemetry;

    const txInSessionCount = sessionTelemetry.filter(e => e.event_type === 'transaction_created').length || 1;
    const failedEventsCount = sessionTelemetry.filter(e => ['transaction_failed', 'login_failed'].includes(e.event_type)).length;
    const sessionDevices = new Set(sessionTelemetry.map(e => e.device_id || e.device_type).filter(Boolean));
    const deviceChangesCount = Math.max(0, sessionDevices.size - 1);

    const isRapid = sessionDurationSeconds !== null && sessionDurationSeconds <= 30;

    let sessionScore = 0;
    let sessionSeverity = 'LOW';
    let sessionReason = 'Session duration and activity are within normal parameters.';

    if (isRapid && !isKnownDevice && amount > avgAmount && avgAmount > 0) {
      sessionScore = 15;
      sessionSeverity = 'HIGH';
      sessionReason = `Suspicious rapid login on new device followed by transaction within ${sessionDurationSeconds}s.`;
    } else if (isRapid && sessionDurationSeconds <= 15) {
      sessionScore = 10;
      sessionSeverity = 'MEDIUM';
      sessionReason = `Rapid transaction executed within ${sessionDurationSeconds} seconds of session login.`;
    } else if (failedEventsCount >= 2 || deviceChangesCount >= 2) {
      sessionScore = 10;
      sessionSeverity = 'MEDIUM';
      sessionReason = `Multiple failed events (${failedEventsCount}) or device changes (${deviceChangesCount}) detected in session.`;
    }

    risk_factors.session_behavior = {
      session_id: currentSessionId,
      session_duration_seconds: sessionDurationSeconds,
      transactions_in_session: txInSessionCount,
      failed_events_in_session: failedEventsCount,
      device_changes_in_session: deviceChangesCount,
      rapid_transaction_detected: isRapid,
      score: sessionScore,
      severity: sessionSeverity,
      explanation: sessionReason,
      reason: sessionReason
    };
    totalScore += sessionScore;

    // ==========================================
    // SIGNAL 5B: SESSION FINANCIAL CUMULATIVE AMOUNT & ACTIVITY (Max +25)
    // ==========================================
    const sessionSummary = await transactionService.getSessionTransactionSummary(currentSessionId, userId);

    const sessionTxCount = sessionSummary.transaction_count || 1;
    const sessionTotalAmount = sessionSummary.total_amount_transacted || amount;
    const sessionAvgAmount = sessionSummary.average_transaction_amount || amount;
    const sessionUniqueReceivers = sessionSummary.unique_receiver_count || 1;
    const txns5mCount = sessionSummary.transactions_in_last_5_minutes || 1;
    const amount5m = sessionSummary.amount_in_last_5_minutes || amount;

    let velocityInSession = 'normal';
    if (sessionDurationSeconds && sessionDurationSeconds > 0) {
      const txPerMin = (sessionTxCount / sessionDurationSeconds) * 60;
      if (txPerMin >= 2) velocityInSession = 'high';
    }

    let sessionActScore = 0;
    let sessionActSeverity = 'LOW';
    let sessionActReason = 'Session cumulative transaction amount is within normal bounds.';

    if (sessionTotalAmount >= 25000 || (avgAmount > 0 && sessionTotalAmount > avgAmount * 6)) {
      sessionActScore = 25;
      sessionActSeverity = 'CRITICAL';
      sessionActReason = `High cumulative session amount (₹${sessionTotalAmount} transferred across ${sessionTxCount} transactions).`;
    } else if (sessionTotalAmount >= 15000 || (avgAmount > 0 && sessionTotalAmount > avgAmount * 3.5)) {
      sessionActScore = 15;
      sessionActSeverity = 'HIGH';
      sessionActReason = `Elevated cumulative session amount (₹${sessionTotalAmount} transferred in current session).`;
    } else if (sessionTotalAmount >= 8000 || (avgAmount > 0 && sessionTotalAmount > avgAmount * 2)) {
      sessionActScore = 10;
      sessionActSeverity = 'MEDIUM';
      sessionActReason = `Moderate cumulative session amount (₹${sessionTotalAmount} transferred in current session).`;
    }

    risk_factors.session_activity = {
      session_id: currentSessionId,
      transaction_count: sessionTxCount,
      transaction_count_in_session: sessionTxCount,
      total_amount_transacted: sessionTotalAmount,
      total_amount_transacted_in_session: sessionTotalAmount,
      average_transaction_amount: sessionAvgAmount,
      average_transaction_amount_in_session: sessionAvgAmount,
      unique_receiver_count: sessionUniqueReceivers,
      unique_receiver_count_in_session: sessionUniqueReceivers,
      transactions_in_last_5_minutes: txns5mCount,
      amount_in_last_5_minutes: amount5m,
      transaction_velocity_in_session: velocityInSession,
      score: sessionActScore,
      severity: sessionActSeverity,
      explanation: sessionActReason,
      reason: sessionActReason
    };
    totalScore += sessionActScore;

    // ==========================================
    // SIGNAL 6: TIME-OF-DAY ANOMALY (Max +10)
    // ==========================================
    const txDate = new Date(transaction.transaction_timestamp || transaction.created_at);
    const currentHour = txDate.getHours();

    const previousTxHours = previousSentTxns
      .map(t => new Date(t.transaction_timestamp || t.created_at).getHours())
      .filter(h => !isNaN(h));

    let timeScore = 0;
    let timeSeverity = 'LOW';
    let typicalRange = '06:00 - 23:00';
    let timeReason = `Transaction time (${String(currentHour).padStart(2, '0')}:00) is consistent with normal activity patterns.`;

    if (previousTxHours.length >= 3) {
      const minH = Math.min(...previousTxHours);
      const maxH = Math.max(...previousTxHours);
      typicalRange = `${String(minH).padStart(2, '0')}:00 - ${String(maxH).padStart(2, '0')}:00`;

      if (!previousTxHours.includes(currentHour) && (currentHour < minH - 2 || currentHour > maxH + 2)) {
        timeScore = 10;
        timeSeverity = 'MEDIUM';
        timeReason = `Transaction executed at ${String(currentHour).padStart(2, '0')}:00, which deviates from historical active hours (${typicalRange}).`;
      }
    } else {
      if (currentHour >= 1 && currentHour <= 5) {
        timeScore = 10;
        timeSeverity = 'MEDIUM';
        timeReason = `Transaction executed during unusual late-night hours (${String(currentHour).padStart(2, '0')}:00).`;
      }
    }

    risk_factors.time_of_day_anomaly = {
      current_transaction_hour: currentHour,
      typical_hours_range: typicalRange,
      score: timeScore,
      severity: timeSeverity,
      explanation: timeReason,
      reason: timeReason
    };
    totalScore += timeScore;

    // ==========================================
    // SIGNAL 7: RECEIVER PATTERN (Max +15)
    // ==========================================
    const receiverId = transaction.receiver_user_id;
    const isKnownReceiver = previousSentTxns.some(t => t.receiver_user_id === receiverId);

    let receiverScore = 0;
    let receiverSeverity = 'LOW';
    let receiverReason = `Receiver '${receiverId}' is a recognized prior recipient.`;

    const repeatedInSession = sessionSummary.repeated_receiver_count || 0;
    if (repeatedInSession >= 3) {
      receiverScore = 15;
      receiverSeverity = 'HIGH';
      receiverReason = `Repeated rapid transfers sent to the same recipient during current session.`;
    } else if (sessionUniqueReceivers >= 3) {
      receiverScore = 15;
      receiverSeverity = 'HIGH';
      receiverReason = `Rapid money distribution across ${sessionUniqueReceivers} unique receivers during current session.`;
    } else if (!isKnownReceiver) {
      receiverScore = 5;
      receiverSeverity = 'LOW';
      receiverReason = `Receiver '${receiverId}' has not previously appeared in user transaction history.`;
    }

    risk_factors.new_receiver = {
      receiver_id: receiverId,
      is_known_receiver: isKnownReceiver,
      score: receiverScore,
      severity: receiverSeverity,
      explanation: receiverReason,
      reason: receiverReason
    };
    risk_factors.receiver_pattern = { ...risk_factors.new_receiver };
    totalScore += receiverScore;

    // --- FINAL SCORE & CLASSIFICATION ---
    const finalScore = Math.min(100, Math.max(0, totalScore));
    const classification = classifyRiskScore(finalScore);

    // Construct Contributing Signals & Explanations
    const contributing_signals = [];

    if (velocityScore > 0) {
      contributing_signals.push(`${tx_5m} transactions detected within 5 minutes (High velocity)`);
    }
    if (sessionActScore > 0) {
      contributing_signals.push(`₹${sessionTotalAmount} transferred in this session (High cumulative amount)`);
    }
    if (amountScore > 0) {
      contributing_signals.push(`Single transaction amount (₹${amount}) deviates from user baseline average (₹${avgAmount})`);
    }
    if (splitScore > 0) {
      contributing_signals.push(`Multiple transactions show a possible split-payment pattern (${recent15mSentTxns.length} similar-sized transactions)`);
    }
    if (receiverScore >= 10) {
      contributing_signals.push(receiverReason);
    }
    if (deviceScore > 0) {
      contributing_signals.push(`New or unrecognized device detected (${browser} on ${operating_system})`);
    }
    if (locationScore > 0) {
      contributing_signals.push(`Unusual location detected (${currentLocation})`);
    }
    if (sessionScore > 0) {
      contributing_signals.push(`Rapid transaction execution within ${sessionDurationSeconds}s of login`);
    }

    if (contributing_signals.length === 0) {
      contributing_signals.push("Transaction behavior is consistent with the user's normal activity.");
    }

    let summary_reason = '';
    if (classification.risk_level === 'CRITICAL' || classification.risk_level === 'HIGH') {
      summary_reason = `Multiple suspicious behaviors detected: ${contributing_signals.join('; ')}.`;
    } else if (classification.risk_level === 'MEDIUM') {
      summary_reason = `Moderate behavioral deviation detected: ${contributing_signals.join('; ')}.`;
    } else {
      summary_reason = "Transaction behavior is consistent with the user's normal activity.";
    }

    risk_factors.contributing_signals = contributing_signals;
    risk_factors.summary_reason = summary_reason;
    risk_factors.reason = summary_reason;

    // Baseline Snapshot
    const baseline_snapshot = {
      average_transaction_amount: baseline.average_transaction_amount,
      transaction_count: baseline.transaction_count,
      average_daily_transactions: baseline.average_daily_transactions,
      common_device_type: baseline.common_device_type,
      common_device_id: baseline.common_device_id,
      common_location: baseline.common_location,
      common_transaction_type: baseline.common_transaction_type,
      average_session_duration_seconds: baseline.average_session_duration_seconds,
      last_calculated_at: baseline.last_calculated_at
    };

    // Construct Risk Decision Entity
    const riskDecisionId = identityService.generateRiskDecisionId();
    const riskDecisionData = {
      risk_decision_id: riskDecisionId,
      transaction_id: transactionId,
      user_id: userId,
      risk_score: finalScore,
      risk_level: classification.risk_level,
      decision: classification.decision,
      risk_factors,
      baseline_snapshot,
      created_at: new Date().toISOString()
    };

    // 5. Persist to Supabase risk_decisions table
    return await riskRepository.createRiskDecision(riskDecisionData);
  },

  /**
   * Retrieves risk decisions for an authenticated user (newest first)
   */
  async getUserRiskDecisions(userId) {
    if (!userId) {
      throw new Error('User ID is required to retrieve risk decisions.');
    }
    return await riskRepository.getRiskDecisionsForUser(userId);
  }
};
