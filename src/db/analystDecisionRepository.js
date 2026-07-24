/**
 * Analyst Decision Repository (Supabase PostgreSQL Integration with In-Memory Fallback)
 * Manages database persistence for analyst decision workflows, case assignments, dynamic statistics, and audit trails.
 */

import { supabase } from './supabaseClient.js';
import { CENTRALIZED_ANALYSTS, getAnalystByEmailOrId } from '../analyst/analystsConfig.js';

// In-memory fallback stores
const inMemoryDecisions = new Map();
const inMemoryCaseAssignments = new Map();

export const analystDecisionRepository = {
  /**
   * Persists a formal analyst decision record
   */
  async saveDecision(decisionData) {
    const id = decisionData.id || `DEC-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).substring(2, 6).toUpperCase()}`;
    const now = new Date().toISOString();
    const analystInfo = getAnalystByEmailOrId(decisionData.analyst_email || decisionData.analyst_id);

    const record = {
      id,
      analyst_id: analystInfo.analyst_id,
      analyst_name: analystInfo.name,
      analyst_email: analystInfo.email,
      session_id: decisionData.session_id,
      transaction_id: decisionData.transaction_id || null,
      user_id: decisionData.user_id || null,
      threat_type: decisionData.threat_type || 'ACCOUNT_TAKEOVER_RISK',
      risk_score: parseFloat(decisionData.risk_score) || 0,
      decision: decisionData.decision || 'APPROVED', // APPROVED, REJECTED, BLOCKED, HELD, ESCALATED
      decision_reason: decisionData.decision_reason || 'Reviewed session evidence and verified activity.',
      analyst_notes: decisionData.analyst_notes || null,
      previous_status: decisionData.previous_status || 'PENDING_REVIEW',
      new_status: decisionData.new_status || decisionData.decision,
      insider_event_id: decisionData.insider_event_id || null,
      created_at: decisionData.created_at || now,
      updated_at: now
    };

    // Store in memory map
    inMemoryDecisions.set(id, record);

    // Also update case assignment status to reflect new decision
    if (record.session_id) {
      this.assignCase(record.session_id, record.analyst_id, record.analyst_email, record.new_status);
    }

    // Try persisting to Supabase if table exists
    try {
      const { data, error } = await supabase
        .from('analyst_decisions')
        .insert([record])
        .select()
        .maybeSingle();

      if (error) {
        console.warn('⚠️ Supabase analyst_decisions Insert Warning:', error.message);
      } else if (data) {
        inMemoryDecisions.set(id, { ...record, ...data });
        return { ...record, ...data };
      }
    } catch (e) {
      console.warn('Notice: analyst_decisions table insert notice:', e.message);
    }

    return record;
  },

  /**
   * Retrieves all decisions recorded across the platform
   */
  async getAllDecisions() {
    let dbDecisions = [];
    try {
      const { data, error } = await supabase
        .from('analyst_decisions')
        .select('*')
        .order('created_at', { ascending: false });

      if (!error && data) dbDecisions = data;
    } catch (e) {}

    const memDecisions = Array.from(inMemoryDecisions.values());
    const map = new Map();
    [...memDecisions, ...dbDecisions].forEach(d => map.set(d.id, d));

    return Array.from(map.values()).sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
  },

  /**
   * Retrieves decisions for a specific session ID
   */
  async getDecisionsForSession(sessionId) {
    if (!sessionId) return [];
    const all = await this.getAllDecisions();
    return all.filter(d => d.session_id === sessionId);
  },

  /**
   * Retrieves latest decision for a specific session ID
   */
  async getLatestDecisionForSession(sessionId) {
    const list = await this.getDecisionsForSession(sessionId);
    return list.length > 0 ? list[0] : null;
  },

  /**
   * Assigns or reassigns case ownership for a high risk session
   */
  assignCase(sessionId, analystId, analystEmail, status = 'UNDER_REVIEW') {
    if (!sessionId) return null;
    const analystInfo = getAnalystByEmailOrId(analystEmail || analystId);

    const assignment = {
      session_id: sessionId,
      assigned_analyst_id: analystInfo.analyst_id,
      assigned_analyst_name: analystInfo.name,
      assigned_analyst_email: analystInfo.email,
      status: status,
      assigned_at: new Date().toISOString()
    };

    inMemoryCaseAssignments.set(sessionId, assignment);
    return assignment;
  },

  /**
   * Retrieves current case assignment for a session
   */
  getCaseAssignment(sessionId) {
    if (!sessionId) return null;
    return inMemoryCaseAssignments.get(sessionId) || null;
  },

  /**
   * Retrieves all case assignments
   */
  getAllCaseAssignments() {
    return Array.from(inMemoryCaseAssignments.values());
  },

  /**
   * Dynamically computes statistics for a given analyst (or overall if no analyst ID provided)
   */
  async getAnalystStatistics(analystIdOrEmail) {
    const allDecisions = await this.getAllDecisions();
    const targetAnalyst = analystIdOrEmail ? getAnalystByEmailOrId(analystIdOrEmail) : null;

    const filtered = targetAnalyst
      ? allDecisions.filter(d => 
          d.analyst_email?.toLowerCase() === targetAnalyst.email.toLowerCase() || 
          d.analyst_id === targetAnalyst.analyst_id
        )
      : allDecisions;

    const approvedCount = filtered.filter(d => d.decision === 'APPROVED').length;
    const rejectedCount = filtered.filter(d => d.decision === 'REJECTED').length;
    const blockedCount = filtered.filter(d => d.decision === 'BLOCKED').length;
    const heldCount = filtered.filter(d => d.decision === 'HELD').length;
    const escalatedCount = filtered.filter(d => d.decision === 'ESCALATED').length;
    const totalReviews = filtered.length;

    // Calculate pending reviews assigned to this analyst
    const allAssignments = Array.from(inMemoryCaseAssignments.values());
    const assignedPending = targetAnalyst 
      ? allAssignments.filter(a => a.assigned_analyst_email?.toLowerCase() === targetAnalyst.email.toLowerCase() && (a.status === 'UNDER_REVIEW' || a.status === 'PENDING_REVIEW')).length
      : allAssignments.filter(a => a.status === 'UNDER_REVIEW' || a.status === 'PENDING_REVIEW').length;

    const lastActivity = filtered.length > 0 ? filtered[0].created_at : new Date().toISOString();

    return {
      analyst_id: targetAnalyst ? targetAnalyst.analyst_id : 'ALL',
      name: targetAnalyst ? targetAnalyst.name : 'All Analysts',
      email: targetAnalyst ? targetAnalyst.email : 'all@finspark.com',
      total_reviews: totalReviews,
      approved_count: approvedCount,
      rejected_count: rejectedCount,
      blocked_count: blockedCount,
      held_count: heldCount,
      escalated_count: escalatedCount,
      pending_count: assignedPending,
      last_activity: lastActivity
    };
  }
};
