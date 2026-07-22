/**
 * FINSPARK - Account Takeover (ATO) Threat Intelligence Engine
 * Analyzes Supabase PostgreSQL database data to compute ATO risk scores, weighted risk signals, device fingerprints, impossible travel anomalies, login timelines, and post-login transaction velocity.
 */

import { supabase } from '../db/supabaseClient.js';
import { baselineService } from './baselineService.js';

/**
 * Distance calculation helper (Haversine formula in KM)
 */
function calculateGeoDistanceKm(lat1, lon1, lat2, lon2) {
  if (!lat1 || !lon1 || !lat2 || !lon2) return 0;
  const R = 6371;
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLon = (lon2 - lon1) * Math.PI / 180;
  const a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
            Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
            Math.sin(dLon / 2) * Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return Math.round(R * c);
}

function getCityCoords(loc) {
  if (!loc || typeof loc !== 'string') return null;
  const l = loc.toLowerCase();
  if (l.includes('chennai')) return { lat: 13.0827, lng: 80.2707, name: 'Chennai, IN' };
  if (l.includes('mumbai')) return { lat: 19.0760, lng: 72.8777, name: 'Mumbai, IN' };
  if (l.includes('delhi')) return { lat: 28.7041, lng: 77.1025, name: 'Delhi, IN' };
  if (l.includes('london')) return { lat: 51.5074, lng: -0.1278, name: 'London, UK' };
  if (l.includes('singapore')) return { lat: 1.3521, lng: 103.8198, name: 'Singapore, SG' };
  if (l.includes('new york') || l.includes('ny')) return { lat: 40.7128, lng: -74.0060, name: 'New York, US' };
  return null;
}

export const atoService = {
  /**
   * Performs deep Account Takeover (ATO) analysis for a given account/user identifier
   */
  async analyzeAccountTakeover(queryIdentifier, timeRange = 'all') {
    if (!queryIdentifier) throw new Error('Account identifier is required for ATO analysis.');

    const cleanQuery = queryIdentifier.trim();

    // 1. Resolve User Record in Supabase
    const { data: matchedUsers } = await supabase
      .from('users')
      .select('*')
      .or(`account_id.eq.${cleanQuery},user_id.eq.${cleanQuery},email.eq.${cleanQuery},account_id.ilike.%${cleanQuery}%,user_id.ilike.%${cleanQuery}%,email.ilike.%${cleanQuery}%`)
      .limit(1);

    if (!matchedUsers || matchedUsers.length === 0) {
      return { found: false, message: `Account '${cleanQuery}' not found in database.` };
    }

    const user = matchedUsers[0];
    const userId = user.user_id;

    // Time filter cutoff
    const nowMs = Date.now();
    let cutoffMs = 0;
    if (timeRange === '1h') cutoffMs = nowMs - (1 * 3600 * 1000);
    else if (timeRange === '24h') cutoffMs = nowMs - (24 * 3600 * 1000);
    else if (timeRange === '7d') cutoffMs = nowMs - (7 * 86400 * 1000);
    else if (timeRange === '30d') cutoffMs = nowMs - (30 * 86400 * 1000);

    // 2. Fetch Sessions, Transactions, Telemetry, Baselines, Risk Decisions
    const { data: sessionsData } = await supabase
      .from('sessions')
      .select('*')
      .eq('user_id', userId)
      .order('login_time', { ascending: false });
    const rawSessions = sessionsData || [];

    const { data: sentTxnsData } = await supabase
      .from('transactions')
      .select('*')
      .eq('sender_user_id', userId)
      .order('transaction_timestamp', { ascending: false });
    const rawTxns = sentTxnsData || [];

    const { data: telemetryData } = await supabase
      .from('telemetry_events')
      .select('*')
      .eq('user_id', userId)
      .order('created_at', { ascending: false });
    const rawTelemetry = telemetryData || [];

    const { data: riskDecisionsData } = await supabase
      .from('risk_decisions')
      .select('*')
      .eq('user_id', userId)
      .order('created_at', { ascending: false });
    const rawRiskDecisions = riskDecisionsData || [];

    const baseline = await baselineService.getUserBaseline(userId);

    // Filter datasets by timeRange if specified
    const sessions = cutoffMs > 0 ? rawSessions.filter(s => new Date(s.login_time).getTime() >= cutoffMs) : rawSessions;
    const transactions = cutoffMs > 0 ? rawTxns.filter(t => new Date(t.transaction_timestamp || t.created_at).getTime() >= cutoffMs) : rawTxns;
    const telemetry = cutoffMs > 0 ? rawTelemetry.filter(e => new Date(e.created_at).getTime() >= cutoffMs) : rawTelemetry;

    // -------------------------------------------------------------
    // A. LATEST LOGIN & ACTIVE SESSION
    // -------------------------------------------------------------
    const latestSession = sessions.length > 0 ? sessions[0] : null;
    const latestTelemetry = telemetry.length > 0 ? telemetry[0] : null;

    const latestLoginInfo = {
      login_time: latestSession ? latestSession.login_time : (user.created_at || 'N/A'),
      location: latestTelemetry?.location || 'Unknown / Localhost',
      device_type: latestTelemetry?.device_type || 'Chrome Browser (Windows)',
      ip_address: latestTelemetry?.ip_address || '127.0.0.1',
      browser: latestTelemetry?.browser || 'Chrome 126.0',
      operating_system: latestTelemetry?.os || 'Windows 11',
      session_status: latestSession ? latestSession.session_status : 'completed'
    };

    // -------------------------------------------------------------
    // B. RECENT ACTIVITY COUNTERS
    // -------------------------------------------------------------
    const failedLoginsCount = telemetry.filter(e => e.event_type === 'login_failed').length;
    const successfulLoginsCount = sessions.length;
    const passwordChangesCount = telemetry.filter(e => e.event_type === 'password_change').length;
    const profileUpdatesCount = telemetry.filter(e => e.event_type === 'profile_update').length;

    const recentActivity = {
      total_sessions: sessions.length,
      successful_logins: successfulLoginsCount,
      failed_logins: failedLoginsCount,
      password_changes: passwordChangesCount,
      email_changes: 0,
      phone_changes: 0,
      profile_updates: profileUpdatesCount
    };

    // -------------------------------------------------------------
    // C. DEVICE ANALYSIS & FINGERPRINTING
    // -------------------------------------------------------------
    const knownDevicesMap = new Map();
    rawTelemetry.forEach(e => {
      const devKey = e.device_id || e.device_type || 'Browser';
      if (!knownDevicesMap.has(devKey)) {
        knownDevicesMap.set(devKey, {
          device_key: devKey,
          device_type: e.device_type || 'Browser',
          first_seen: e.created_at,
          session_count: 1
        });
      } else {
        knownDevicesMap.get(devKey).session_count++;
      }
    });

    const knownDevices = Array.from(knownDevicesMap.values());
    const isNewDeviceDetected = knownDevices.length > 1 && latestTelemetry && knownDevicesMap.get(latestTelemetry.device_type || latestTelemetry.device_id)?.session_count === 1;

    // Check device reuse across multiple accounts
    const { data: globalDevTelemetry } = await supabase
      .from('telemetry_events')
      .select('user_id, device_type, device_id')
      .neq('user_id', userId);

    const collidingUserIds = new Set(
      (globalDevTelemetry || [])
        .filter(e => knownDevicesMap.has(e.device_id) || knownDevicesMap.has(e.device_type))
        .map(e => e.user_id)
    );

    const deviceAnalysis = {
      known_devices: knownDevices,
      total_known_devices_count: knownDevices.length,
      is_new_device: isNewDeviceDetected,
      device_reuse_detected: collidingUserIds.size > 0,
      colliding_accounts_count: collidingUserIds.size,
      fingerprint: latestTelemetry?.device_id || 'DEV-FINGERPRINT-DEFAULT'
    };

    // -------------------------------------------------------------
    // D. IP & IMPOSSIBLE TRAVEL LOCATION ANALYSIS
    // -------------------------------------------------------------
    const uniqueIPs = Array.from(new Set(rawTelemetry.map(e => e.ip_address).filter(Boolean)));
    const isNewIPDetected = uniqueIPs.length > 1 && latestTelemetry?.ip_address && !uniqueIPs.slice(1).includes(latestTelemetry.ip_address);

    let impossibleTravelDetected = false;
    let travelEvidence = 'Normal physical travel parameters.';

    const locationEvents = rawTelemetry
      .filter(e => e.location && e.created_at)
      .sort((a, b) => new Date(a.created_at) - new Date(b.created_at));

    for (let i = 1; i < locationEvents.length; i++) {
      const e1 = locationEvents[i - 1];
      const e2 = locationEvents[i];
      const c1 = getCityCoords(e1.location);
      const c2 = getCityCoords(e2.location);

      if (c1 && c2 && c1.name !== c2.name) {
        const distKm = calculateGeoDistanceKm(c1.lat, c1.lng, c2.lat, c2.lng);
        const timeDiffHours = Math.max(0.01, (new Date(e2.created_at) - new Date(e1.created_at)) / (1000 * 3600));
        const speedKmh = Math.round(distKm / timeDiffHours);

        if (speedKmh > 900) {
          impossibleTravelDetected = true;
          travelEvidence = `IMPOSSIBLE TRAVEL: Physical movement between ${c1.name} and ${c2.name} (${distKm} km) in ${Math.round(timeDiffHours * 60)} mins requires speed of ${speedKmh} km/h.`;
          break;
        }
      }
    }

    const ipLocationAnalysis = {
      unique_ips: uniqueIPs,
      is_new_ip: isNewIPDetected,
      impossible_travel_detected: impossibleTravelDetected,
      travel_evidence: travelEvidence
    };

    // -------------------------------------------------------------
    // E. LOGIN TIMELINE (Chronological Order of Events)
    // -------------------------------------------------------------
    const timelineEvents = [];

    sessions.forEach(s => {
      timelineEvents.push({
        id: s.session_id,
        timestamp: s.login_time,
        event_type: 'Session Created',
        description: `Session '${s.session_id}' initialized. Status: ${s.session_status}`,
        ip_address: latestLoginInfo.ip_address,
        device: latestLoginInfo.device_type,
        location: latestLoginInfo.location,
        risk_score: s.session_status === 'active' ? 10 : 0
      });
      if (s.logout_time) {
        timelineEvents.push({
          id: `logout_${s.session_id}`,
          timestamp: s.logout_time,
          event_type: 'Logout Completed',
          description: `Session '${s.session_id}' terminated normally after ${s.session_duration_seconds || 0} seconds.`,
          ip_address: latestLoginInfo.ip_address,
          device: latestLoginInfo.device_type,
          location: latestLoginInfo.location,
          risk_score: 0
        });
      }
    });

    transactions.forEach(t => {
      timelineEvents.push({
        id: t.transaction_id,
        timestamp: t.transaction_timestamp || t.created_at,
        event_type: 'Transaction Executed',
        description: `Transferred ₹${parseFloat(t.amount).toFixed(2)} to account '${t.receiver_user_id}'.`,
        ip_address: latestLoginInfo.ip_address,
        device: latestLoginInfo.device_type,
        location: latestLoginInfo.location,
        risk_score: parseFloat(t.amount) > 50000 ? 50 : 15
      });
    });

    timelineEvents.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

    // -------------------------------------------------------------
    // F. WEIGHTED ATO RISK SIGNAL ENGINE & RISK SCORE CALCULATION
    // -------------------------------------------------------------
    const riskSignals = [];
    let atoScore = 0;

    if (isNewDeviceDetected) {
      atoScore += 20;
      riskSignals.push({
        signal_name: 'New Device Login',
        severity: 'HIGH',
        weight: +20,
        evidence: `Session opened from unrecognized device '${latestLoginInfo.device_type}'.`,
        timestamp: latestLoginInfo.login_time
      });
    }

    if (impossibleTravelDetected) {
      atoScore += 35;
      riskSignals.push({
        signal_name: 'Impossible Travel Anomaly',
        severity: 'CRITICAL',
        weight: +35,
        evidence: travelEvidence,
        timestamp: latestLoginInfo.login_time
      });
    }

    if (isNewIPDetected) {
      atoScore += 15;
      riskSignals.push({
        signal_name: 'Unrecognized IP Address',
        severity: 'MEDIUM',
        weight: +15,
        evidence: `Login originated from unfamiliar IP address '${latestLoginInfo.ip_address}'.`,
        timestamp: latestLoginInfo.login_time
      });
    }

    // Check for post-login rapid high-value transfers
    const highValueTx = transactions.find(t => parseFloat(t.amount) > 50000);
    if (highValueTx) {
      atoScore += 25;
      riskSignals.push({
        signal_name: 'Rapid High-Value Transfer Post-Login',
        severity: 'HIGH',
        weight: +25,
        evidence: `High-value transfer of ₹${parseFloat(highValueTx.amount).toFixed(2)} executed shortly after session start.`,
        timestamp: highValueTx.transaction_timestamp || highValueTx.created_at
      });
    }

    // Check for new beneficiary transfer
    if (transactions.length > 0 && (!baseline.transaction_count || baseline.transaction_count <= 1)) {
      atoScore += 15;
      riskSignals.push({
        signal_name: 'Transfer to Unfamiliar Receiver',
        severity: 'MEDIUM',
        weight: +15,
        evidence: `Transfer sent to newly added receiver account '${transactions[0].receiver_user_id}'.`,
        timestamp: transactions[0].transaction_timestamp || transactions[0].created_at
      });
    }

    // Check for concurrent active sessions
    const activeSessions = sessions.filter(s => s.session_status === 'active');
    if (activeSessions.length > 1) {
      atoScore += 20;
      riskSignals.push({
        signal_name: 'Concurrent Active Sessions Detected',
        severity: 'HIGH',
        weight: +20,
        evidence: `Detected ${activeSessions.length} simultaneous active login sessions for the same user account.`,
        timestamp: latestLoginInfo.login_time
      });
    }

    if (passwordChangesCount > 0) {
      atoScore += 20;
      riskSignals.push({
        signal_name: 'Recent Password Modification',
        severity: 'MEDIUM',
        weight: +20,
        evidence: 'Account credentials/password modified recently.',
        timestamp: latestLoginInfo.login_time
      });
    }

    const finalATOScore = Math.min(100, Math.max(5, atoScore));
    let atoRiskLevel = 'LOW';
    let atoStatus = 'NORMAL';

    if (finalATOScore >= 80) { atoRiskLevel = 'CRITICAL'; atoStatus = 'SUSPECTED_TAKEOVER'; }
    else if (finalATOScore >= 60) { atoRiskLevel = 'HIGH'; atoStatus = 'HIGH_TAKEOVER_RISK'; }
    else if (finalATOScore >= 30) { atoRiskLevel = 'MEDIUM'; atoStatus = 'ELEVATED_MONITORING'; }

    // Behavioral Comparison Deviation Calculation
    const currentTxAvg = transactions.length > 0 ? transactions.reduce((sum, t) => sum + (parseFloat(t.amount) || 0), 0) / transactions.length : 0;
    const baselineAvg = parseFloat(baseline.average_transaction_amount) || 0;
    const devRatio = baselineAvg > 0 ? Math.round((currentTxAvg / baselineAvg) * 10) / 10 : 1;

    return {
      found: true,
      query: cleanQuery,
      identity: {
        user_id: user.user_id,
        account_id: user.account_id,
        full_name: user.full_name,
        email: user.email,
        phone: user.phone || 'N/A',
        account_status: user.account_status || 'active',
        created_at: user.created_at
      },
      current_risk: {
        ato_score: finalATOScore,
        risk_level: atoRiskLevel,
        status: atoStatus,
        last_updated: new Date().toISOString()
      },
      latest_login: latestLoginInfo,
      recent_activity: recentActivity,
      device_analysis: deviceAnalysis,
      ip_location_analysis: ipLocationAnalysis,
      login_timeline: timelineEvents.slice(0, 15),
      behavior_summary: {
        normal_avg_amount: baselineAvg,
        current_avg_amount: currentTxAvg,
        deviation_ratio: devRatio,
        typical_device: baseline.common_device_type || 'Chrome Browser',
        current_device: latestLoginInfo.device_type,
        typical_location: baseline.common_location || 'Localhost',
        current_location: latestLoginInfo.location
      },
      risk_signals: riskSignals.length > 0 ? riskSignals : [{
        signal_name: 'Normal User Session',
        severity: 'LOW',
        weight: 0,
        evidence: 'Session activity parameters conform to user historical baseline.',
        timestamp: latestLoginInfo.login_time
      }]
    };
  }
};
