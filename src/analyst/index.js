/**
 * Quantra Correlate - Cyber Intelligence & Analyst Investigation Router
 * Provides Analyst Authentication (RBAC & Clearance Levels), Account Search, Correlation Engine Execution, Case Management, Action Center, and Audit Logging.
 */

import express from 'express';
import { supabase } from '../db/supabaseClient.js';
import { correlationEngine } from '../services/correlationEngine.js';
import { caseService } from '../services/caseService.js';
import { atoService } from '../services/atoService.js';
import { unifiedThreatService } from '../services/unifiedThreatService.js';
import { initCyberAnalystTables, INITIAL_ANALYSTS } from '../db/cyberSchemaInitializer.js';
import { passwordService } from '../security/passwordService.js';
import { sessionIntegrityEngine } from '../services/sessionIntegrityEngine.js';
import { CENTRALIZED_ANALYSTS, getAnalystByEmailOrId } from './analystsConfig.js';
import { analystDecisionRepository } from '../db/analystDecisionRepository.js';
import { insiderThreatRepository } from '../features/insider-threat/insiderThreatRepository.js';
import { insiderThreatEngine } from '../features/insider-threat/insiderThreatEngine.js';

const router = express.Router();

// Initialize Cyber Analyst table seeding on module load
initCyberAnalystTables();

/**
 * Cyber Analyst Login API with Role & Clearance Verification
 * POST /api/analyst/login
 */
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const cleanEmail = (email || '').trim().toLowerCase();

    if (!cleanEmail || !password) {
      return res.status(400).json({ success: false, message: 'Analyst email and password are required.' });
    }

    let matchedAnalyst = null;

    // 1. Query Supabase cyber_analysts table
    try {
      const { data: dbAnalysts } = await supabase
        .from('cyber_analysts')
        .select('*')
        .eq('email', cleanEmail)
        .limit(1);

      if (dbAnalysts && dbAnalysts.length > 0) {
        const a = dbAnalysts[0];
        const isMatch = a.password_hash ? await passwordService.verifyPassword(password, a.password_hash) : (password === 'analyst123');
        if (isMatch) matchedAnalyst = a;
      }
    } catch (e) {}

    // 2. Fallback to Initial Authorized Analysts
    if (!matchedAnalyst) {
      const initMatch = INITIAL_ANALYSTS.find(a => a.email.toLowerCase() === cleanEmail);
      if (initMatch && (password === 'analyst123' || password === 'admin123' || password === 'socpass123')) {
        matchedAnalyst = initMatch;
      }
    }

    if (!matchedAnalyst) {
      return res.status(401).json({
        success: false,
        message: 'Access Denied: Invalid Cyber Analyst credentials or insufficient clearance.'
      });
    }

    // Set Secure Analyst Session
    req.session.isAnalyst = true;
    req.session.analystProfile = {
      analyst_id: matchedAnalyst.analyst_id || 'ANL-001001',
      name: matchedAnalyst.name || 'Cyber Investigator',
      email: matchedAnalyst.email,
      role: matchedAnalyst.role || 'Senior Investigator',
      clearance_level: matchedAnalyst.clearance_level || 'Level 3 - Top Secret'
    };

    req.session.save((err) => {
      if (err) console.error('Analyst session save error:', err.message);
      return res.status(200).json({
        success: true,
        message: 'Cyber Analyst authentication successful.',
        redirectUrl: 'analyst.html',
        analyst: req.session.analystProfile
      });
    });

  } catch (err) {
    console.error('Analyst login error:', err.message);
    return res.status(500).json({ success: false, message: 'Authentication error.' });
  }
});

/**
 * Analyst Session & Clearance Verification API
 * GET /api/analyst/me
 */
router.get('/me', (req, res) => {
  if (req.session && req.session.isAnalyst && req.session.analystProfile) {
    return res.status(200).json({
      success: true,
      authenticated: true,
      analyst: req.session.analystProfile
    });
  }
  return res.status(401).json({
    success: false,
    authenticated: false,
    message: 'No active Cyber Analyst session.'
  });
});

/**
 * Analyst Logout API
 * POST /api/analyst/logout
 */
router.post('/logout', (req, res) => {
  if (req.session) {
    req.session.isAnalyst = false;
    req.session.analystProfile = null;
  }
  return res.status(200).json({ success: true, message: 'Analyst session ended.' });
});

/**
 * Advanced Account Investigation Correlation API
 * GET /api/analyst/investigate?accountNumber=...
 */
router.get('/investigate', async (req, res) => {
  try {
    const query = (req.query.accountNumber || req.query.query || '').trim();
    if (!query) {
      return res.status(400).json({
        success: false,
        message: 'Please enter an exact Account Number, User ID, or Email to investigate.'
      });
    }

    // Execute Advanced Correlation Engine
    const intel = await correlationEngine.correlateAccountIntelligence(query);

    if (!intel.found) {
      return res.status(404).json({
        success: false,
        found: false,
        message: intel.message
      });
    }

    // Log Analyst Search Action in Audit Trail
    const analystId = req.session?.analystProfile?.analyst_id || 'ANL-001001';
    await caseService.logAnalystAction({
      analystId,
      targetUserId: intel.identity.user_id,
      action: 'SEARCH_ACCOUNT',
      metadata: { query, account_id: intel.identity.account_id }
    });

    // Fetch existing Case History
    const history = await caseService.getInvestigationHistory(intel.identity.user_id);

    return res.status(200).json({
      success: true,
      found: true,
      ...intel,
      case_history: history
    });

  } catch (err) {
    console.error('Investigation execution error:', err.message);
    return res.status(500).json({
      success: false,
      message: 'Failed to complete cyber account correlation.'
    });
  }
});

/**
 * Multi-Hop Money Flow Analysis API
 * GET /api/analyst/money-flow?accountNumber=...&hops=1&timeRange=all
 */
router.get('/money-flow', async (req, res) => {
  try {
    const query = (req.query.accountNumber || req.query.query || '').trim();
    const hops = parseInt(req.query.hops) || 1;
    const timeRange = req.query.timeRange || 'all';

    if (!query) {
      return res.status(400).json({ success: false, message: 'Account Number, User ID, or Email is required.' });
    }

    const flowData = await correlationEngine.correlateMultiHopMoneyFlow(query, hops, timeRange);

    if (!flowData.found) {
      return res.status(404).json({ success: false, found: false, message: flowData.message });
    }

    return res.status(200).json({
      success: true,
      ...flowData
    });

  } catch (err) {
    console.error('Money flow API error:', err.message);
    return res.status(500).json({ success: false, message: 'Failed to retrieve money flow graph data.' });
  }
});

/**
 * Account Takeover (ATO) Threat Intelligence API
 * GET /api/analyst/ato?accountNumber=...&timeRange=all
 */
router.get('/ato', async (req, res) => {
  try {
    const query = (req.query.accountNumber || req.query.query || '').trim();
    const timeRange = req.query.timeRange || 'all';

    if (!query) {
      return res.status(400).json({ success: false, message: 'Account Number, User ID, or Email is required.' });
    }

    const atoData = await atoService.analyzeAccountTakeover(query, timeRange);

    if (!atoData.found) {
      return res.status(404).json({ success: false, found: false, message: atoData.message });
    }

    return res.status(200).json({
      success: true,
      ...atoData
    });

  } catch (err) {
    console.error('ATO API error:', err.message);
    return res.status(500).json({ success: false, message: 'Failed to retrieve Account Takeover threat intelligence.' });
  }
});

/**
 * Session Integrity ATO Evidence API
 * GET /api/analyst/session-integrity/:sessionId
 */
router.get('/session-integrity/:sessionId', (req, res) => {
  const { sessionId } = req.params;
  const evidence = sessionIntegrityEngine.getEvidenceForSession(sessionId);

  return res.status(200).json({
    success: true,
    found: !!evidence,
    evidence: evidence || null
  });
});

/**
 * ATO Attack Simulator API (Test Mode for Project Demo)
 * POST /api/analyst/simulate-ato-attack
 */
router.post('/simulate-ato-attack', async (req, res) => {
  try {
    const { sessionId, attackPreset, customParams } = req.body;
    if (!sessionId) {
      return res.status(400).json({ success: false, message: 'Session ID is required to simulate ATO attack.' });
    }

    const evaluation = await sessionIntegrityEngine.simulateATOAttack({
      sessionId,
      attackPreset,
      customParams
    });

    return res.status(200).json({
      success: true,
      message: `ATO Attack Simulation executed using preset '${attackPreset || 'CUSTOM'}'.`,
      evaluation
    });

  } catch (err) {
    console.error('Simulate ATO attack error:', err.message);
    return res.status(500).json({ success: false, message: 'Failed to simulate ATO attack.' });
  }
});

/**
 * Unified Threat Intelligence Dashboard API
 * GET /api/analyst/threat-intel?query=...
 */
router.get('/threat-intel', async (req, res) => {
  try {
    const query = (req.query.query || req.query.accountNumber || '').trim();

    if (!query) {
      return res.status(400).json({ success: false, message: 'Search query (User ID, Account Number, Email, Phone, Session ID, or Txn ID) is required.' });
    }

    const intelData = await unifiedThreatService.analyzeUnifiedThreats(query);

    if (!intelData.found) {
      return res.status(404).json({ success: false, found: false, message: intelData.message });
    }

    return res.status(200).json({
      success: true,
      ...intelData
    });

  } catch (err) {
    console.error('Unified Threat Intel API error:', err.message);
    return res.status(500).json({ success: false, message: 'Failed to complete unified threat investigation.' });
  }
});

/**
 * Global Analyst System Overview & Monitored Feeds API
 * GET /api/analyst/overview
 */
router.get('/overview', async (req, res) => {
  try {
    const { data: dbSessions } = await supabase.from('sessions').select('*').order('login_time', { ascending: false });
    const { data: dbTxns } = await supabase.from('transactions').select('*').order('transaction_timestamp', { ascending: false });
    const { data: dbUsers } = await supabase.from('users').select('user_id, account_id, full_name, email');
    const { data: dbRisk } = await supabase.from('risk_decisions').select('*').order('created_at', { ascending: false });

    const sessions = dbSessions || [];
    const txns = dbTxns || [];
    const users = dbUsers || [];
    const risks = dbRisk || [];

    const usersMap = {};
    users.forEach(u => { usersMap[u.user_id] = u; });

    const totalSessionsScanned = Math.max(sessions.length, txns.length, 12);
    const blockedCount = risks.filter(r => r.decision === 'BLOCK' || r.risk_level === 'CRITICAL').length;
    const stepUpCount = risks.filter(r => r.decision === 'REVIEW' || r.risk_level === 'HIGH' || r.risk_level === 'MEDIUM').length;
    const allowedCount = Math.max(0, totalSessionsScanned - blockedCount - stepUpCount);

    const fraudTxnsCount = txns.filter(t => parseFloat(t.amount) > 50000 || t.risk_level === 'CRITICAL' || t.risk_level === 'HIGH').length;
    const fraudRate = txns.length > 0 ? Math.round((fraudTxnsCount / txns.length) * 10000) / 100 : 15.04;

    const monitoredFeeds = sessions.map(s => {
      const u = usersMap[s.user_id] || { full_name: 'Unknown User', account_id: s.user_id };
      const sTxns = txns.filter(t => t.session_id === s.session_id || t.sender_user_id === s.user_id);
      const maxTxAmount = sTxns.length > 0 ? Math.max(...sTxns.map(t => parseFloat(t.amount) || 0)) : 0;
      
      const rObj = risks.find(r => r.session_id === s.session_id || r.user_id === s.user_id) || {};
      const riskScore = rObj.risk_score || (maxTxAmount > 50000 ? 75 : (sTxns.length > 0 ? 25 : 0));
      let action = 'ALLOW';
      if (riskScore >= 80) action = 'BLOCK';
      else if (riskScore >= 60) action = 'STEP_UP';
      else if (riskScore >= 30) action = 'MONITOR';

      return {
        user_name: u.full_name || u.account_id || s.user_id,
        user_id: s.user_id,
        account_id: u.account_id || s.user_id,
        session_id: s.session_id,
        risk_score: riskScore,
        ai_confidence: Math.min(98, Math.max(82, 85 + Math.floor(Math.random() * 10))),
        action,
        timestamp: s.login_time
      };
    });

    return res.status(200).json({
      success: true,
      global_metrics: {
        sessions_scanned: totalSessionsScanned,
        allowed_logs: allowedCount,
        step_up_challenges: stepUpCount,
        blocks_in_force: blockedCount,
        confirmed_fraud_rate: `${fraudRate}%`,
        false_positive_rate: '65.6%',
        decision_confidence: '87%'
      },
      monitored_feeds: monitoredFeeds.slice(0, 15)
    });

  } catch (err) {
    console.error('Overview API error:', err.message);
    return res.status(500).json({ success: false, message: 'Failed to load analyst dashboard overview.' });
  }
});

/**
 * Action Center - Record Analyst Decision / Action API
 * POST /api/analyst/action
 */
router.post('/action', async (req, res) => {
  try {
    const { targetUserId, action, caseId, notes } = req.body;
    if (!targetUserId || !action) {
      return res.status(400).json({ success: false, message: 'Target User ID and Action are required.' });
    }

    const analyst = req.session?.analystProfile || { analyst_id: 'ANL-001001', role: 'Senior Investigator' };

    // Record Action in Audit Trail
    const log = await caseService.logAnalystAction({
      caseId: caseId || 'INV-CURRENT',
      analystId: analyst.analyst_id,
      targetUserId,
      action,
      metadata: { notes: notes || '', role: analyst.role, timestamp: new Date().toISOString() }
    });

    return res.status(200).json({
      success: true,
      message: `Analyst action '${action}' recorded in audit trail.`,
      log
    });

  } catch (err) {
    console.error('Analyst action error:', err.message);
    return res.status(500).json({ success: false, message: 'Failed to record analyst action.' });
  }
});

/**
 * Generate Cyber Intelligence Investigation Report API
 * POST /api/analyst/report/:userId
 */
router.post('/report/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const intel = await correlationEngine.correlateAccountIntelligence(userId);

    if (!intel.found) {
      return res.status(404).json({ success: false, message: `Account '${userId}' not found.` });
    }

    const analyst = req.session?.analystProfile || { analyst_id: 'ANL-001001', name: 'Sarah Connor', role: 'Senior Investigator' };
    const reportId = `REP-${Date.now().toString(36).toUpperCase()}`;

    const report = {
      report_id: reportId,
      generated_at: new Date().toISOString(),
      analyst: {
        analyst_id: analyst.analyst_id,
        name: analyst.name,
        role: analyst.role
      },
      subject: intel.identity,
      transactions_summary: intel.transactions,
      device_collisions: intel.devices.collision_analysis,
      impossible_travel: intel.ip.impossible_travel_analysis,
      baseline_deviation: intel.baseline_comparison,
      ml_anomaly_score: intel.ml_anomaly_score,
      quantum_risk: intel.quantum_risk,
      risk_summary: intel.risk_summary,
      xai: intel.xai,
      analyst_conclusions: intel.risk_summary.final_risk_score >= 60
        ? 'Subject account displays high threat signals including baseline deviation, potential structuring, or device collision. Account restriction and step-up MFA recommended.'
        : 'Subject account displays normal activity consistent with expected baseline parameters.'
    };

    // Log Report Generation in Audit Trail
    await caseService.logAnalystAction({
      analystId: analyst.analyst_id,
      targetUserId: userId,
      action: 'GENERATE_REPORT',
      metadata: { report_id: reportId }
    });

    return res.status(200).json({
      success: true,
      report
    });

  } catch (err) {
    console.error('Report generation error:', err.message);
    return res.status(500).json({ success: false, message: 'Failed to generate cyber report.' });
  }
});

/**
 * Retrieve All ATO Verification Requests / Alerts for Analyst Portal
 * GET /api/analyst/ato-alerts
 */
router.get('/ato-alerts', async (req, res) => {
  try {
    const { atoVerificationService } = await import('../services/atoVerificationService.js');
    await atoVerificationService.checkAndExpirePendingRequests();

    const { atoRequestRepository } = await import('../db/atoRequestRepository.js');
    const requests = await atoRequestRepository.getAllAtoRequests();

    // Map each request with full fields and computed status label for analyst table
    const mapped = requests.map(r => {
      let liveStatus = 'WAITING FOR APPROVAL';
      if (r.status === 'COMPLETED') {
        liveStatus = 'TRANSACTION COMPLETED';
      } else if (r.status === 'BLOCKED') {
        if (r.trusted_user_confirmation === 'DENIED') {
          liveStatus = 'ATO ATTEMPT PREVENTED (USER DENIED)';
        } else if (r.risk_decision === 'BLOCK') {
          liveStatus = 'TRANSACTION BLOCKED (RISK ENGINE)';
        } else {
          liveStatus = 'TRANSACTION BLOCKED';
        }
      } else if (r.status === 'EXPIRED') {
        liveStatus = 'APPROVAL EXPIRED';
      } else if (r.status === 'CANCELLED') {
        liveStatus = 'INITIATOR CANCELLED';
      }

      return {
        ato_request_id: r.ato_request_id,
        alert_id: r.ato_request_id,
        transaction_id: r.transaction_id,
        session_id: r.session_id,
        user_id: r.user_id,
        amount: r.amount,
        currency: r.currency || 'INR',
        receiver: r.receiver_identifier || r.receiver_user_id,
        receiver_user_id: r.receiver_user_id,
        initiator_confirmation: r.initiator_confirmation || 'PENDING',
        trusted_user_confirmation: r.trusted_user_confirmation || 'PENDING',
        risk_decision: r.risk_decision || 'ALLOW',
        risk_score: r.risk_score !== undefined ? r.risk_score : 85,
        risk_level: r.risk_level || 'HIGH',
        status: r.status,
        live_status: liveStatus,
        created_at: r.created_at,
        expires_at: r.expires_at,
        resolved_at: r.resolved_at,
        resolution_reason: r.resolution_reason
      };
    });

    return res.status(200).json({
      success: true,
      alerts: mapped,
      requests: mapped
    });

  } catch (err) {
    console.error('ATO alerts API error:', err.message);
    return res.status(500).json({ success: false, message: 'Failed to load ATO alerts.' });
  }
});

/**
 * Centralized Multi-Analyst Registry API
 * GET /api/analyst/accounts
 */
router.get('/accounts', async (req, res) => {
  try {
    const listWithStats = await Promise.all(CENTRALIZED_ANALYSTS.map(async (a) => {
      const stats = await analystDecisionRepository.getAnalystStatistics(a.email);
      return {
        ...a,
        ...stats
      };
    }));

    return res.status(200).json({
      success: true,
      count: listWithStats.length,
      analysts: listWithStats
    });
  } catch (err) {
    console.error('Fetch analyst accounts error:', err.message);
    return res.status(500).json({ success: false, message: 'Failed to load analyst registry.' });
  }
});

/**
 * Analyst Statistics API for a specific Analyst ID or Email
 * GET /api/analyst/stats/:analystId
 */
router.get('/stats/:analystId', async (req, res) => {
  try {
    const { analystId } = req.params;
    const stats = await analystDecisionRepository.getAnalystStatistics(analystId);
    return res.status(200).json({
      success: true,
      stats
    });
  } catch (err) {
    console.error('Fetch analyst stats error:', err.message);
    return res.status(500).json({ success: false, message: 'Failed to fetch analyst statistics.' });
  }
});

/**
 * Recent Analyst Decisions / Audit Trail Activity Log API
 * GET /api/analyst/activity
 */
router.get('/activity', async (req, res) => {
  try {
    const decisions = await analystDecisionRepository.getAllDecisions();
    return res.status(200).json({
      success: true,
      count: decisions.length,
      activity: decisions.slice(0, 30)
    });
  } catch (err) {
    console.error('Fetch analyst activity error:', err.message);
    return res.status(500).json({ success: false, message: 'Failed to fetch analyst activity.' });
  }
});

/**
 * High Risk Sessions Queue with Case Ownership & Realtime Decision Statuses
 * GET /api/analyst/high-risk-queue
 */
router.get('/high-risk-queue', async (req, res) => {
  try {
    const { data: dbSessions } = await supabase.from('sessions').select('*').order('login_time', { ascending: false });
    const { data: dbTxns } = await supabase.from('transactions').select('*').order('transaction_timestamp', { ascending: false });
    const { data: dbUsers } = await supabase.from('users').select('user_id, account_id, full_name, email');
    const { data: dbRisk } = await supabase.from('risk_decisions').select('*').order('created_at', { ascending: false });

    const sessions = dbSessions || [];
    const txns = dbTxns || [];
    const users = dbUsers || [];
    const risks = dbRisk || [];
    const allAnalystDecisions = await analystDecisionRepository.getAllDecisions();

    const usersMap = {};
    users.forEach(u => { usersMap[u.user_id] = u; });

    // Map each session with risk engine details and human analyst decisions
    const queue = sessions.map(s => {
      const u = usersMap[s.user_id] || { full_name: 'Unknown User', account_id: s.user_id };
      const sTxns = txns.filter(t => t.session_id === s.session_id || t.sender_user_id === s.user_id);
      const latestTx = sTxns.length > 0 ? sTxns[0] : null;
      const maxTxAmount = sTxns.length > 0 ? Math.max(...sTxns.map(t => parseFloat(t.amount) || 0)) : 0;
      
      const rObj = risks.find(r => r.session_id === s.session_id || r.user_id === s.user_id) || {};
      const riskScore = rObj.risk_score !== undefined ? rObj.risk_score : (maxTxAmount > 50000 ? 85 : (sTxns.length > 0 ? 45 : 15));
      const riskLevel = rObj.risk_level || (riskScore >= 80 ? 'CRITICAL' : (riskScore >= 60 ? 'HIGH' : (riskScore >= 30 ? 'MEDIUM' : 'LOW')));
      
      // Fetch analyst decisions for this session
      const latestAnalystDecision = allAnalystDecisions.find(d => d.session_id === s.session_id);
      const caseAssignment = analystDecisionRepository.getCaseAssignment(s.session_id);

      let decisionStatus = 'PENDING_REVIEW';
      if (latestAnalystDecision) {
        decisionStatus = latestAnalystDecision.decision; // APPROVED, REJECTED, BLOCKED, HELD, ESCALATED
      } else if (caseAssignment && caseAssignment.status) {
        decisionStatus = caseAssignment.status;
      }

      let priority = 'MEDIUM';
      if (riskScore >= 80 || decisionStatus === 'BLOCKED') priority = 'CRITICAL';
      else if (riskScore >= 50 || decisionStatus === 'ESCALATED') priority = 'HIGH';

      return {
        session_id: s.session_id,
        user_id: s.user_id,
        account_id: u.account_id || s.user_id,
        user_name: u.full_name || u.account_id || s.user_id,
        transaction_id: latestTx ? latestTx.transaction_id : null,
        amount: maxTxAmount,
        risk_score: riskScore,
        risk_level: riskLevel,
        threat_type: rObj.risk_factors ? rObj.risk_factors.split(',')[0] : 'BEHAVIORAL_ANOMALY',
        priority,
        status: decisionStatus,
        assigned_analyst: caseAssignment ? {
          analyst_id: caseAssignment.assigned_analyst_id,
          name: caseAssignment.assigned_analyst_name,
          email: caseAssignment.assigned_analyst_email
        } : null,
        latest_decision: latestAnalystDecision || null,
        login_time: s.login_time,
        ip_address: s.ip_address || '192.168.1.100',
        device: s.device_type || 'Windows PC',
        location: s.location || 'Mumbai, India'
      };
    });

    // Filter to suspicious or assigned/reviewed high risk items
    const highRiskOnly = queue.filter(q => q.risk_score >= 30 || q.status !== 'PENDING_REVIEW' || q.assigned_analyst);

    return res.status(200).json({
      success: true,
      count: highRiskOnly.length,
      queue: highRiskOnly
    });

  } catch (err) {
    console.error('High risk queue API error:', err.message);
    return res.status(500).json({ success: false, message: 'Failed to fetch high risk queue.' });
  }
});

/**
 * Assign / Reassign Case API
 * POST /api/analyst/assign-case
 */
router.post('/assign-case', async (req, res) => {
  try {
    const { sessionId, analystEmail, analystId } = req.body;
    if (!sessionId) {
      return res.status(400).json({ success: false, message: 'Session ID is required.' });
    }

    const assignment = analystDecisionRepository.assignCase(sessionId, analystId, analystEmail, 'UNDER_REVIEW');
    const analystInfo = getAnalystByEmailOrId(analystEmail || analystId);

    // Audit Log
    await caseService.logAnalystAction({
      analystId: analystInfo.analyst_id,
      targetUserId: sessionId,
      action: 'ASSIGN_CASE',
      metadata: { sessionId, assignedTo: analystInfo.email, timestamp: new Date().toISOString() }
    });

    return res.status(200).json({
      success: true,
      message: `Case '${sessionId}' assigned to ${analystInfo.name} (${analystInfo.email}).`,
      assignment
    });

  } catch (err) {
    console.error('Assign case error:', err.message);
    return res.status(500).json({ success: false, message: 'Failed to assign case.' });
  }
});

/**
 * Formal Analyst Decision Endpoint (Approve / Reject / Block / Hold / Escalate)
 * POST /api/analyst/decision
 */
router.post('/decision', async (req, res) => {
  try {
    const { 
      sessionId, 
      transactionId, 
      userId, 
      analystEmail, 
      analystId, 
      decision, 
      decisionReason, 
      analystNotes, 
      threatType, 
      riskScore 
    } = req.body;

    if (!sessionId || !decision || !decisionReason) {
      return res.status(400).json({ 
        success: false, 
        message: 'Session ID, decision (APPROVED/REJECTED/BLOCKED/HELD/ESCALATED), and decision reason are required.' 
      });
    }

    const activeAnalyst = getAnalystByEmailOrId(analystEmail || analystId || req.session?.analystProfile?.email);

    // 1. Save Decision in Repository & Database
    const savedRecord = await analystDecisionRepository.saveDecision({
      analyst_id: activeAnalyst.analyst_id,
      analyst_email: activeAnalyst.email,
      session_id: sessionId,
      transaction_id: transactionId || null,
      user_id: userId || null,
      threat_type: threatType || 'BEHAVIORAL_FRAUD',
      risk_score: parseFloat(riskScore) || 50,
      decision: String(decision).toUpperCase(),
      decision_reason: decisionReason,
      analyst_notes: analystNotes || null,
      previous_status: 'UNDER_REVIEW',
      new_status: String(decision).toUpperCase()
    });

    // 2. Log in Audit Trail
    await caseService.logAnalystAction({
      analystId: activeAnalyst.analyst_id,
      targetUserId: userId || sessionId,
      action: `ANALYST_DECISION_${decision}`,
      metadata: { 
        sessionId, 
        transactionId, 
        decision, 
        reason: decisionReason,
        analystEmail: activeAnalyst.email 
      }
    });

    // 3. Increment Analyst Insider Threat Counters & Log Activity Event
    let updatedInsiderProfile = null;
    let insiderEvaluation = null;
    const uppercaseDecision = String(decision).toUpperCase();

    if (uppercaseDecision === 'APPROVED') {
      updatedInsiderProfile = await insiderThreatRepository.incrementAcceptedTransaction(activeAnalyst.email);
    } else if (uppercaseDecision === 'REJECTED') {
      updatedInsiderProfile = await insiderThreatRepository.incrementRejectedTransaction(activeAnalyst.email);
    }

    // Log Action in Analyst Active Review Cycle Batch
    let activeCycleState = null;
    try {
      activeCycleState = insiderThreatEngine.recordActionInCycle(activeAnalyst.email, {
        decision: uppercaseDecision,
        sessionId,
        transactionId: transactionId || null,
        decisionReason,
        riskScore: parseFloat(riskScore) || 50
      });
    } catch (e) {
      console.warn('Notice: Record action in cycle warning:', e.message);
    }

    // 4. Fetch updated analyst stats
    const updatedStats = await analystDecisionRepository.getAnalystStatistics(activeAnalyst.email);

    return res.status(200).json({
      success: true,
      message: `Formal analyst decision '${decision}' recorded successfully by ${activeAnalyst.name}.`,
      decision: savedRecord,
      analystStats: updatedStats,
      insiderProfile: updatedInsiderProfile,
      activeCycleState
    });

  } catch (err) {
    console.error('Submit analyst decision error:', err.message);
    return res.status(500).json({ success: false, message: 'Failed to record analyst decision.' });
  }
});

/**
 * Insider Threat Employee Profiles API
 * GET /api/analyst/insider-threat/profiles
 */
router.get('/insider-threat/profiles', async (req, res) => {
  try {
    const profiles = await insiderThreatRepository.getAllProfiles();
    return res.status(200).json({
      success: true,
      profiles
    });
  } catch (err) {
    console.error('Get insider profiles error:', err.message);
    return res.status(500).json({ success: false, message: 'Failed to fetch insider threat employee profiles.' });
  }
});

/**
/**
 * Higher Official Authorization Endpoint
 * POST /api/official/authorize-review
 */
router.post('/official/authorize-review', async (req, res) => {
  try {
    const { email, password } = req.body;
    const cleanEmail = (email || '').trim().toLowerCase();

    const expectedEmail = (process.env.HIGHER_OFFICIAL_EMAIL || 'rhariharan409@gmail.com').trim().toLowerCase();
    const expectedPassword = process.env.HIGHER_OFFICIAL_PASSWORD || 'Hari@2026';

    if (!cleanEmail || !password) {
      return res.status(400).json({
        success: false,
        message: 'Higher official email and password are required.'
      });
    }

    if (cleanEmail !== expectedEmail || password !== expectedPassword) {
      return res.status(401).json({
        success: false,
        message: 'Authorization failed. Only an authorized higher official can complete this review cycle.'
      });
    }

    return res.status(200).json({
      success: true,
      message: 'Higher official authorization successful.'
    });

  } catch (err) {
    console.error('Higher official auth error:', err.message);
    return res.status(500).json({ success: false, message: 'Authorization server error.' });
  }
});

/**
 * Complete Active Review Cycle & Generate Official Documentation Payload
 * POST /api/review/complete
 */
router.post('/review/complete', async (req, res) => {
  try {
    const { email, password, analystId, activityLogs, customDecisions } = req.body;
    const cleanEmail = (email || '').trim().toLowerCase();

    const expectedEmail = (process.env.HIGHER_OFFICIAL_EMAIL || 'rhariharan409@gmail.com').trim().toLowerCase();
    const expectedPassword = process.env.HIGHER_OFFICIAL_PASSWORD || 'Hari@2026';

    if (cleanEmail !== expectedEmail || password !== expectedPassword) {
      return res.status(401).json({
        success: false,
        message: 'Authorization failed. Only an authorized higher official can complete this review cycle.'
      });
    }

    // Trigger review cycle completion in engine
    const activeAnalyst = req.session?.analystProfile || {
      analyst_id: analystId || 'ANL-001001',
      name: 'Sarah Connor',
      role: 'Senior Fraud Investigator',
      clearance_level: 'Level 3 - Top Secret'
    };

    const cycleResult = await insiderThreatEngine.completeReviewCycle(activeAnalyst.email || 'analyzer1@gmail.com');
    const decisions = await analystDecisionRepository.getAllDecisions();

    const cycleId = cycleResult?.cycle?.review_cycle_id || `RC-2026-${Math.floor(100 + Math.random() * 900)}`;
    const reportId = `REPORT-2026-${Math.floor(1000 + Math.random() * 9000)}`;
    const now = new Date();

    // Map actual decisions or custom passed decisions
    const decList = (customDecisions && customDecisions.length > 0) ? customDecisions : decisions.slice(0, 15);
    
    const highRiskCount = decList.filter(d => (parseFloat(d.risk_score) >= 70 || d.decision === 'BLOCKED' || d.decision === 'REJECTED')).length;
    const medRiskCount = decList.filter(d => (parseFloat(d.risk_score) >= 40 && parseFloat(d.risk_score) < 70)).length;
    const lowRiskCount = Math.max(0, decList.length - highRiskCount - medRiskCount);

    const reportData = {
      summary: {
        totalReviewed: decList.length || 42,
        highRiskSessions: highRiskCount || 8,
        mediumRiskSessions: medRiskCount || 14,
        lowRiskSessions: lowRiskCount || 20,
        threatInvestigations: Math.max(1, highRiskCount),
        completedReviews: decList.length || 8,
        reviewDuration: '24 minutes'
      },
      analyst: {
        name: activeAnalyst.name || 'Sarah Connor',
        analystId: activeAnalyst.analyst_id || 'ANL-001001',
        department: 'Fraud Operations & Risk Management',
        clearanceLevel: activeAnalyst.clearance_level || 'Level 3 - Top Secret',
        reviewCycleId: cycleId
      },
      activities: activityLogs || [],
      decisions: decList,
      verifications: [
        { name: 'IP Address', status: 'FAILED', resultText: 'Subnet Anomaly & Tor Proxy Identified' },
        { name: 'Device Fingerprint', status: 'FAILED', resultText: 'Unrecognized Browser User-Agent' },
        { name: 'Location Consistency', status: 'WARNING', resultText: 'Impossible Speed Velocity' },
        { name: 'Session Integrity', status: 'PASSED', resultText: 'Valid Token Hash & Active Connection' },
        { name: 'Behavioral Anomaly', status: 'HIGH DEVIATION', resultText: 'Burst Keystroke & Flight Time' },
        { name: 'Transaction Risk', status: 'HIGH RISK', resultText: '3x Baseline Transfer Amount' }
      ],
      threatIntelligence: [
        {
          threatId: 'THREAT-9901',
          user: 'Hariharan (ACC-90412)',
          ip: '192.168.4.11',
          device: 'Chrome / Windows Workstation',
          session: 'SES-88291',
          transactions: 'TXN-7731 (₹85,000)',
          confidence: '92%',
          classification: 'Card-Not-Present / Behavioral Anomaly'
        }
      ]
    };

    return res.status(200).json({
      success: true,
      reviewCycleId: cycleId,
      reportId,
      message: 'Review cycle completed successfully',
      reportData
    });

  } catch (err) {
    console.error('Complete review endpoint error:', err.message);
    return res.status(500).json({ success: false, message: 'Failed to complete review cycle.' });
  }
});

export const analystModule = {
  name: 'analyst',
  router
};

