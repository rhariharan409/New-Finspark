/**
 * ATO Verification Requests Repository (Supabase PostgreSQL Integration with In-Memory Fallback)
 * Manages database persistence for controlled Account Takeover verification and dual-approval workflows.
 */

import { supabase } from './supabaseClient.js';

// In-Memory Fallback Store for ATO requests
const inMemoryAtoRequests = new Map();

export const atoRequestRepository = {
  /**
   * Creates a new ATO Verification Request
   */
  async createAtoRequest(requestData) {
    const requestId = requestData.ato_request_id || `ATO-REQ-${Date.now().toString(36).toUpperCase()}`;
    const now = new Date();
    const expiresAt = requestData.expires_at || new Date(now.getTime() + 5 * 60 * 1000).toISOString(); // 5 minute expiration

    const record = {
      id: requestData.id || requestId,
      ato_request_id: requestId,
      transaction_id: requestData.transaction_id,
      session_id: requestData.session_id,
      user_id: requestData.user_id,
      amount: parseFloat(requestData.amount) || 0,
      currency: requestData.currency || 'INR',
      receiver_user_id: requestData.receiver_user_id,
      receiver_identifier: requestData.receiver_identifier || requestData.receiver_user_id,
      description: requestData.description || '',
      initiator_confirmation: requestData.initiator_confirmation || 'PENDING',
      trusted_user_confirmation: requestData.trusted_user_confirmation || 'PENDING',
      approval_status: requestData.approval_status || requestData.trusted_user_confirmation || 'WAITING',
      approval_token: requestData.approval_token || `TOK-${Math.random().toString(36).substring(2, 10).toUpperCase()}`,
      approval_method: requestData.approval_method || 'EMAIL_TOKEN',
      security_check_status: requestData.security_check_status || 'PASSED',
      weighted_risk_score: requestData.weighted_risk_score !== undefined ? requestData.weighted_risk_score : 30,
      itemized_verifications: requestData.itemized_verifications || null,
      risk_decision: requestData.risk_decision || 'PENDING',
      risk_score: requestData.risk_score !== undefined ? requestData.risk_score : 30,
      risk_level: requestData.risk_level || 'MEDIUM',
      status: requestData.status || 'PENDING_VERIFICATION',
      user_approval_status: requestData.trusted_user_confirmation || requestData.user_approval_status || 'PENDING',
      created_at: requestData.created_at || now.toISOString(),
      expires_at: expiresAt,
      initiator_confirmed_at: requestData.initiator_confirmed_at || null,
      trusted_user_confirmed_at: requestData.trusted_user_confirmed_at || null,
      approval_requested_at: requestData.approval_requested_at || now.toISOString(),
      approval_completed_at: requestData.approval_completed_at || null,
      resolved_at: requestData.resolved_at || null,
      resolution_reason: requestData.resolution_reason || null,
      blocked_reason: requestData.blocked_reason || null
    };

    // Store in memory first
    inMemoryAtoRequests.set(requestId, record);

    // Persist to Supabase if table exists
    try {
      const { data, error } = await supabase
        .from('ato_verification_requests')
        .insert([record])
        .select()
        .maybeSingle();

      if (!error && data) {
        inMemoryAtoRequests.set(requestId, { ...record, ...data });
        return { ...record, ...data };
      }
    } catch (e) {
      console.warn('Supabase ato_verification_requests insert notice:', e.message);
    }

    return record;
  },

  /**
   * Retrieves an ATO request by ID
   */
  async getAtoRequestById(requestId) {
    if (!requestId) return null;

    try {
      const { data, error } = await supabase
        .from('ato_verification_requests')
        .select('*')
        .eq('ato_request_id', requestId)
        .maybeSingle();

      if (!error && data) {
        // Merge with memory record to ensure newest fields
        const mem = inMemoryAtoRequests.get(requestId) || {};
        return { ...mem, ...data };
      }
    } catch (e) {}

    return inMemoryAtoRequests.get(requestId) || null;
  },

  /**
   * Retrieves pending ATO requests for a specific user ID
   */
  async getPendingRequestsForUser(userId) {
    if (!userId) return [];

    let dbRequests = [];
    try {
      const { data, error } = await supabase
        .from('ato_verification_requests')
        .select('*')
        .eq('user_id', userId)
        .or('status.eq.PENDING_VERIFICATION,status.eq.PENDING')
        .order('created_at', { ascending: false });

      if (!error && data) dbRequests = data;
    } catch (e) {}

    // Combine with in-memory records
    const memRequests = Array.from(inMemoryAtoRequests.values())
      .filter(r => r.user_id === userId && (r.status === 'PENDING_VERIFICATION' || r.status === 'PENDING'));

    const map = new Map();
    [...memRequests, ...dbRequests].forEach(r => map.set(r.ato_request_id, r));

    return Array.from(map.values()).sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
  },

  /**
   * Retrieves all ATO requests for Analyst Portal
   */
  async getAllAtoRequests() {
    let dbRequests = [];
    try {
      const { data, error } = await supabase
        .from('ato_verification_requests')
        .select('*')
        .order('created_at', { ascending: false });

      if (!error && data) dbRequests = data;
    } catch (e) {}

    const memRequests = Array.from(inMemoryAtoRequests.values());
    const map = new Map();
    [...memRequests, ...dbRequests].forEach(r => map.set(r.ato_request_id, r));

    return Array.from(map.values()).sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
  },

  /**
   * Updates an ATO request with flexible update fields
   */
  async updateAtoRequest(requestId, updateFields) {
    const existing = await this.getAtoRequestById(requestId);
    if (!existing) throw new Error(`ATO Request '${requestId}' not found.`);

    const updated = {
      ...existing,
      ...updateFields
    };

    // Keep user_approval_status consistent with trusted_user_confirmation
    if (updateFields.trusted_user_confirmation) {
      updated.user_approval_status = updateFields.trusted_user_confirmation;
    }

    inMemoryAtoRequests.set(requestId, updated);

    try {
      await supabase
        .from('ato_verification_requests')
        .update(updated)
        .eq('ato_request_id', requestId);
    } catch (e) {}

    return updated;
  },

  /**
   * Legacy method support for backward compatibility
   */
  async updateAtoRequestStatus(requestId, { status, userApprovalStatus, resolutionReason }) {
    return await this.updateAtoRequest(requestId, {
      status,
      trusted_user_confirmation: userApprovalStatus,
      user_approval_status: userApprovalStatus,
      resolved_at: new Date().toISOString(),
      resolution_reason: resolutionReason
    });
  }
};
