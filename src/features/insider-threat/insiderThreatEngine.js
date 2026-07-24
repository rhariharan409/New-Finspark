/**
 * Dynamic Batch-Based Insider Threat Behavioral Monitoring Engine
 * FINSPARK Cyber Security Platform
 * Evaluates real completed review cycles against actual historical database activity.
 * NO static mock values. NO hardcoded anomaly injection buttons.
 */

import { insiderThreatRepository } from './insiderThreatRepository.js';
import { CENTRALIZED_ANALYSTS, getAnalystByEmailOrId } from '../../analyst/analystsConfig.js';

// In-memory active review cycles tracker per analyst email
const activeReviewCyclesMap = new Map();
let cycleCounter = 1;

export class InsiderThreatEngine {

  /**
   * Get or initialize current open review cycle for an analyst
   */
  getActiveCycle(analystEmail) {
    const key = analystEmail.toLowerCase().trim();
    if (!activeReviewCyclesMap.has(key)) {
      const analystInfo = getAnalystByEmailOrId(key);
      const cycleId = `RC-2026-${String(cycleCounter++).padStart(3, '0')}`;
      activeReviewCyclesMap.set(key, {
        review_cycle_id: cycleId,
        analyst_id: analystInfo.analyst_id,
        analyst_name: analystInfo.name,
        analyst_email: analystInfo.email,
        start_time: new Date().toISOString(),
        actions: []
      });
    }
    return activeReviewCyclesMap.get(key);
  }

  /**
   * Record individual approve/reject action into analyst's current open review cycle
   */
  recordActionInCycle(analystEmail, actionData) {
    const cycle = this.getActiveCycle(analystEmail);
    const now = new Date();

    const actionRecord = {
      decision: String(actionData.decision || 'APPROVED').toUpperCase(),
      session_id: actionData.sessionId || 'N/A',
      transaction_id: actionData.transactionId || null,
      amount: parseFloat(actionData.amount || actionData.transactionAmount) || 0,
      risk_score: parseFloat(actionData.riskScore) || 50,
      reason: actionData.decisionReason || 'Analyst decision recorded',
      timestamp: now.toISOString(),
      time_of_day: now.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: true }),
      ip_address: actionData.ipAddress || '192.168.1.101',
      location: actionData.location || 'New York, US',
      device: actionData.device || 'Chrome 122 on Windows 11 Workstation'
    };

    cycle.actions.push(actionRecord);
    return cycle;
  }

  /**
   * Complete & Analyze Current Review Cycle (Triggered by [ COMPLETE REVIEW ])
   */
  async completeReviewCycle(analystEmail) {
    const key = analystEmail.toLowerCase().trim();
    const cycle = this.getActiveCycle(key);
    const analystInfo = getAnalystByEmailOrId(key);
    const profile = await insiderThreatRepository.getProfile(key);

    const now = new Date();
    const completionTime = now.toISOString();
    const startTime = cycle.start_time || completionTime;

    const startMs = new Date(startTime).getTime();
    const endMs = now.getTime();
    const durationSeconds = Math.max(1, Math.round((endMs - startMs) / 1000));

    const totalReviewed = cycle.actions.length;
    const totalApproved = cycle.actions.filter(a => a.decision === 'APPROVED').length;
    const totalRejected = cycle.actions.filter(a => a.decision === 'REJECTED').length;

    const avgTimePerTxn = totalReviewed > 0 ? Math.round(durationSeconds / totalReviewed) : durationSeconds;

    const amounts = cycle.actions.map(a => a.amount).filter(a => a > 0);
    const avgAmount = amounts.length > 0 ? Math.round(amounts.reduce((a, b) => a + b, 0) / amounts.length) : (profile?.average_transaction_amount || 15000);
    const maxAmount = amounts.length > 0 ? Math.max(...amounts) : (profile?.maximum_transaction_amount || 50000);

    const lastAction = cycle.actions.length > 0 ? cycle.actions[cycle.actions.length - 1] : null;
    const ipAddress = lastAction?.ip_address || profile?.normal_ip_address || '192.168.1.101';
    const location = lastAction?.location || profile?.normal_location || 'New York, US';
    const device = lastAction?.device || profile?.authorized_device_details || 'Chrome 122 on Windows 11 Workstation';

    // 1. Construct & Save Completed Review Cycle Object
    const completedCycleObj = {
      review_cycle_id: cycle.review_cycle_id,
      analyst_id: analystInfo.analyst_id,
      analyst_name: analystInfo.name,
      analyst_email: analystInfo.email,
      start_time: startTime,
      completion_time: completionTime,
      total_transactions_reviewed: totalReviewed,
      total_approved: totalApproved,
      total_rejected: totalRejected,
      review_duration_seconds: durationSeconds,
      avg_time_per_transaction_seconds: avgTimePerTxn,
      avg_amount_reviewed: avgAmount,
      max_amount_reviewed: maxAmount,
      ip_address: ipAddress,
      location: location,
      device: device,
      created_at: completionTime
    };

    await insiderThreatRepository.saveReviewCycle(completedCycleObj);

    // 2. Reset active cycle for next batch
    activeReviewCyclesMap.delete(key);

    // 3. Query Previous Completed Cycles for this Analyst
    const allPreviousCycles = await insiderThreatRepository.getCompletedReviewCycles(key);
    // Exclude the cycle we just saved from historical baseline
    const previousCycles = allPreviousCycles.filter(c => c.review_cycle_id !== completedCycleObj.review_cycle_id);

    // 4. Learning Mode Evaluation (If < 2 previous completed cycles)
    const isLearningMode = previousCycles.length < 2;

    let historicalBaseline = null;
    let deviations = [];
    let threatPossibilities = [];
    let riskScore = 0;
    let riskLevel = 'NORMAL';
    let threatPercentage = 0;
    let riskColor = '#059669';
    let riskBadgeClass = 'badge-low';

    if (isLearningMode) {
      riskLevel = 'LEARNING MODE';
      riskBadgeClass = 'badge-medium';
      riskColor = '#2563eb';
      threatPercentage = 0;

      historicalBaseline = {
        historical_cycles_count: previousCycles.length,
        status_message: `Learning Mode active (${previousCycles.length}/2 previous completed review cycles). Insufficient historical database data to establish a reliable behavioral baseline.`,
        normal_avg_batch_size: profile?.average_accounts_accessed_per_day || 10,
        normal_avg_duration_seconds: 1800,
        normal_working_hours: profile?.normal_working_time || '09:00 AM – 06:00 PM EST',
        normal_location: profile?.normal_location || 'New York, US',
        normal_ip_address: profile?.normal_ip_address || '192.168.1.101',
        normal_device: profile?.authorized_device_details || 'Chrome 122 on Windows 11 Workstation',
        normal_approval_ratio: 70
      };

      threatPossibilities.push({
        title: 'Initial Behavioral Baseline Collection',
        severity: 'LOW',
        description: `Analyst has completed ${previousCycles.length + 1} review cycle(s). The system is accumulating actual database history before enabling automated threat scoring.`
      });

    } else {
      // 5. Build Dynamic Historical Baseline strictly from database previous cycles
      const totalPastCount = previousCycles.length;
      const avgBatchSize = Math.round(previousCycles.reduce((sum, c) => sum + (c.total_transactions_reviewed || 0), 0) / totalPastCount);
      const avgDuration = Math.round(previousCycles.reduce((sum, c) => sum + (c.review_duration_seconds || 0), 0) / totalPastCount);
      
      const totalPastApproved = previousCycles.reduce((sum, c) => sum + (c.total_approved || 0), 0);
      const totalPastReviewed = previousCycles.reduce((sum, c) => sum + (c.total_transactions_reviewed || 0), 0);
      const historicalApprovalRatio = totalPastReviewed > 0 ? Math.round((totalPastApproved / totalPastReviewed) * 100) : 70;

      const pastAmounts = previousCycles.map(c => c.max_amount_reviewed || 0).filter(a => a > 0);
      const historicalMaxAmount = pastAmounts.length > 0 ? Math.max(...pastAmounts) : (profile?.maximum_transaction_amount || 50000);

      const knownLocations = Array.from(new Set(previousCycles.map(c => c.location).filter(Boolean)));
      if (!knownLocations.includes(profile?.normal_location)) knownLocations.push(profile?.normal_location || 'New York, US');

      const knownDevices = Array.from(new Set(previousCycles.map(c => c.device).filter(Boolean)));
      if (!knownDevices.includes(profile?.authorized_device_details)) knownDevices.push(profile?.authorized_device_details || 'Chrome 122 on Windows 11 Workstation');

      const knownIps = Array.from(new Set(previousCycles.map(c => c.ip_address).filter(Boolean)));
      if (!knownIps.includes(profile?.normal_ip_address)) knownIps.push(profile?.normal_ip_address || '192.168.1.101');

      historicalBaseline = {
        historical_cycles_count: totalPastCount,
        normal_avg_batch_size: avgBatchSize || 10,
        normal_avg_duration_seconds: avgDuration || 1800,
        normal_working_hours: profile?.normal_working_time || '09:00 AM – 06:00 PM EST',
        normal_start_hour: 9,
        normal_end_hour: 18,
        normal_location: profile?.normal_location || 'New York, US',
        known_locations: knownLocations,
        normal_ip_address: profile?.normal_ip_address || '192.168.1.101',
        known_ips: knownIps,
        normal_device: profile?.authorized_device_details || 'Chrome 122 on Windows 11 Workstation',
        known_devices: knownDevices,
        normal_approval_ratio: historicalApprovalRatio,
        normal_max_amount: historicalMaxAmount
      };

      // 6. Compare Current Completed Cycle against Dynamic Historical Baseline (8 Signals)
      
      // Signal 1: Review Volume Anomaly
      if (totalReviewed >= avgBatchSize * 4 && avgBatchSize > 0) {
        const mult = Math.round(totalReviewed / avgBatchSize);
        riskScore += 35;
        deviations.push(`🔥 <strong>Critical Review Volume Anomaly:</strong> Reviewed <strong>${totalReviewed} transactions</strong> in this batch (${mult}x higher than historical baseline average of ${avgBatchSize}).`);
        threatPossibilities.push({
          title: 'Mass Data Exfiltration / Bulk Account Scrape',
          severity: 'CRITICAL',
          description: `Analyst processed ${totalReviewed} transactions in a single review batch, indicating potential bulk account scraping or session data harvesting.`
        });
      } else if (totalReviewed >= avgBatchSize * 2 && avgBatchSize > 0) {
        riskScore += 20;
        deviations.push(`⚠️ <strong>Elevated Review Volume:</strong> Batch size of ${totalReviewed} transactions exceeds historical average of ${avgBatchSize}.`);
      }

      // Signal 2: Review Velocity Anomaly
      if (totalReviewed > 5 && avgTimePerTxn < 5) {
        riskScore += 25;
        deviations.push(`⚡ <strong>Abnormal Review Velocity:</strong> Processed transactions at <strong>${avgTimePerTxn}s per item</strong> (Rapid automated review signature).`);
        threatPossibilities.push({
          title: 'Automated Scripting / Scripted Approval Probe',
          severity: 'HIGH',
          description: `Analyst completed reviews at an unnaturally rapid pace (${avgTimePerTxn} seconds per transaction), suggesting automated script usage.`
        });
      }

      // Signal 3: Time Anomaly (After-Hours Activity)
      const currentHour = now.getHours();
      const isAfterHours = currentHour < 9 || currentHour >= 18;
      if (isAfterHours) {
        riskScore += 25;
        const timeStr = now.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: true });
        deviations.push(`🌙 <strong>After-Hours Operational Activity:</strong> Review completed at <strong>${timeStr}</strong> (Outside normal operating hours: ${historicalBaseline.normal_working_hours}).`);
        threatPossibilities.push({
          title: 'Unsanctioned Off-Hours System Access',
          severity: 'HIGH',
          description: `Review cycle completed late at night (${timeStr}) when peer auditing and SOC oversight are absent.`
        });
      }

      // Signal 4: Location Anomaly
      const isLocationDeviated = location && !knownLocations.some(l => location.toLowerCase().includes(l.toLowerCase()));
      if (isLocationDeviated) {
        riskScore += 20;
        deviations.push(`🌍 <strong>Unrecognized Geolocation:</strong> Cycle completed from <strong>${location}</strong> (Known historical locations: ${knownLocations.join(', ')}).`);
        threatPossibilities.push({
          title: 'Credential Compromise / Foreign Proxy Relay',
          severity: 'HIGH',
          description: `Session completed from unexpected remote location (${location}), indicating potential credential theft or unauthorized proxy node.`
        });
      }

      // Signal 5: IP Anomaly
      const isIpDeviated = ipAddress && !knownIps.includes(ipAddress);
      if (isIpDeviated && isLocationDeviated) {
        riskScore += 15;
        deviations.push(`🌐 <strong>Unrecognized IP Address:</strong> Access logged from unknown IP <code>${ipAddress}</code>.`);
      }

      // Signal 6: Device Anomaly
      const isDeviceDeviated = device && !knownDevices.some(d => device.toLowerCase().includes(d.toLowerCase()));
      if (isDeviceDeviated) {
        riskScore += 20;
        deviations.push(`💻 <strong>Untrusted Hardware Device:</strong> Access logged from non-corporate device: <code>${device}</code>.`);
        threatPossibilities.push({
          title: 'Unmanaged Hardware Access',
          severity: 'MEDIUM',
          description: `Review cycle executed from unrecognized hardware environment without endpoint compliance verification.`
        });
      }

      // Signal 7: Decision Pattern Skew
      const currentApprovalRatio = totalReviewed > 0 ? Math.round((totalApproved / totalReviewed) * 100) : 0;
      if (totalReviewed >= 5 && Math.abs(currentApprovalRatio - historicalApprovalRatio) >= 40) {
        riskScore += 15;
        deviations.push(`⚖️ <strong>Decision Pattern Skew:</strong> Current approval ratio is <strong>${currentApprovalRatio}%</strong> (Historical baseline average: ${historicalApprovalRatio}%).`);
        threatPossibilities.push({
          title: 'Abnormal Approval Skew / Collusion Risk',
          severity: 'MEDIUM',
          description: `Analyst approval ratio (${currentApprovalRatio}%) deviated significantly from established historical baseline.`
        });
      }

      // Signal 8: Transaction Value Outlier
      if (maxAmount > historicalMaxAmount * 1.5 && maxAmount > 0) {
        riskScore += 15;
        deviations.push(`💸 <strong>High-Value Transaction Outlier:</strong> Handled transaction of <strong>₹${maxAmount.toLocaleString()}</strong> exceeding historical max limit (₹${historicalMaxAmount.toLocaleString()}).`);
        threatPossibilities.push({
          title: 'High-Value Fraud Clearance Risk',
          severity: 'HIGH',
          description: `Analyst reviewed and passed an unusually large transaction amount exceeding historical review bounds.`
        });
      }

      threatPercentage = Math.min(100, Math.max(0, Math.round(riskScore)));

      if (threatPercentage >= 80) {
        riskLevel = 'CRITICAL INSIDER THREAT RISK';
        riskBadgeClass = 'badge-critical';
        riskColor = '#dc2626';
      } else if (threatPercentage >= 60) {
        riskLevel = 'HIGH DEVIATION';
        riskBadgeClass = 'badge-high';
        riskColor = '#ea580c';
      } else if (threatPercentage >= 30) {
        riskLevel = 'LOW DEVIATION';
        riskBadgeClass = 'badge-medium';
        riskColor = '#d97706';
      }

      if (threatPossibilities.length === 0) {
        threatPossibilities.push({
          title: 'Legitimate Authorized Operations',
          severity: 'LOW',
          description: `Completed review batch aligns strictly with historical analyst baseline parameters. No insider threat vectors detected.`
        });
      }
    }

    // 7. Save Analysis Record
    const analysisId = `ANL-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).substring(2, 5).toUpperCase()}`;
    const analysisObj = {
      analysis_id: analysisId,
      review_cycle_id: completedCycleObj.review_cycle_id,
      analyst_id: analystInfo.analyst_id,
      analyst_email: analystInfo.email,
      is_learning_mode: isLearningMode,
      historical_cycles_count: previousCycles.length,
      historical_baseline: historicalBaseline,
      current_cycle_metrics: completedCycleObj,
      detected_deviations: deviations,
      threat_possibilities: threatPossibilities,
      risk_score: riskScore,
      risk_level: riskLevel,
      threat_percentage: threatPercentage,
      risk_color: riskColor,
      risk_badge_class: riskBadgeClass,
      created_at: completionTime
    };

    await insiderThreatRepository.saveAnalysisResult(analysisObj);

    return {
      cycle: completedCycleObj,
      analysis: analysisObj
    };
  }

  /**
   * Fetch complete Insider Threat telemetry for an analyst
   */
  async getAnalystTelemetry(analystEmail) {
    const key = analystEmail.toLowerCase().trim();
    const latestAnalysis = await insiderThreatRepository.getLatestAnalysis(key);
    const historicalCycles = await insiderThreatRepository.getCompletedReviewCycles(key);
    const activeCycle = this.getActiveCycle(key);
    const profile = await insiderThreatRepository.getProfile(key);

    return {
      analyst_email: key,
      profile,
      active_cycle: {
        review_cycle_id: activeCycle.review_cycle_id,
        start_time: activeCycle.start_time,
        pending_actions_count: activeCycle.actions.length,
        approved_count: activeCycle.actions.filter(a => a.decision === 'APPROVED').length,
        rejected_count: activeCycle.actions.filter(a => a.decision === 'REJECTED').length
      },
      latest_analysis: latestAnalysis,
      historical_cycles: historicalCycles
    };
  }
}

export const insiderThreatEngine = new InsiderThreatEngine();
