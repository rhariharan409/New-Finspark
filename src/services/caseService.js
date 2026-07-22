/**
 * Quantra Correlate - Cyber Analyst Case Management & Audit Logging Service
 * Records investigation cases (INV-YYYYMMDD-XXX) and immutable audit logs in Supabase PostgreSQL.
 */

import { supabase } from '../db/supabaseClient.js';
import { identityService } from '../security/identityService.js';

export const caseService = {
  /**
   * Creates a new investigation case for a target user account
   */
  async createCase({ analystId, targetUserId, targetAccountId, riskScore = 0, decision = 'ALLOW', notes = '' }) {
    const todayStr = new Date().toISOString().replace(/-/g, '').substring(0, 8);
    const randomSuffix = identityService.generateRiskDecisionId().substring(4, 7);
    const caseId = `INV-${todayStr}-${randomSuffix}`;

    const caseData = {
      case_id: caseId,
      analyst_id: analystId || 'ANL-001001',
      target_user_id: targetUserId,
      target_account_id: targetAccountId,
      status: 'UNDER_INVESTIGATION',
      risk_score: riskScore,
      decision: decision,
      notes: notes || 'Investigation case initialized by Cyber Intelligence Analyst.',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };

    try {
      const { data, error } = await supabase
        .from('investigation_cases')
        .insert([caseData])
        .select()
        .single();

      if (error) {
        console.warn('Notice: investigation_cases table write notice:', error.message);
      }
      return data || caseData;

    } catch (err) {
      return caseData;
    }
  },

  /**
   * Logs an immutable analyst action audit trail entry
   */
  async logAnalystAction({ caseId, analystId, targetUserId, action, metadata = {} }) {
    const logData = {
      log_id: `LOG-${identityService.generateEventId().substring(4)}`,
      case_id: caseId || 'INV-GLOBAL',
      analyst_id: analystId || 'ANL-001001',
      target_user_id: targetUserId,
      action: action || 'VIEW_PROFILE',
      timestamp: new Date().toISOString(),
      metadata: metadata || {}
    };

    try {
      const { data, error } = await supabase
        .from('investigation_logs')
        .insert([logData])
        .select()
        .single();

      if (error) {
        console.warn('Notice: investigation_logs table write notice:', error.message);
      }
      return data || logData;

    } catch (err) {
      return logData;
    }
  },

  /**
   * Retrieves investigation history for a user ID
   */
  async getInvestigationHistory(targetUserId) {
    if (!targetUserId) return { cases: [], logs: [] };

    let cases = [];
    let logs = [];

    try {
      const { data: cData } = await supabase
        .from('investigation_cases')
        .select('*')
        .eq('target_user_id', targetUserId)
        .order('created_at', { ascending: false });

      cases = cData || [];

      const { data: lData } = await supabase
        .from('investigation_logs')
        .select('*')
        .eq('target_user_id', targetUserId)
        .order('timestamp', { ascending: false });

      logs = lData || [];

    } catch (err) {}

    return { cases, logs };
  }
};
