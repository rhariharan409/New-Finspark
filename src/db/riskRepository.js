/**
 * Risk Repository (Supabase PostgreSQL Integration)
 * Data Access Layer executing queries against the Supabase risk_decisions table.
 */

import { supabase } from './supabaseClient.js';
import { createRiskDecisionEntity } from '../models/riskModel.js';

// In-memory fallback store
const inMemoryRiskDecisions = new Map();

export const riskRepository = {
  /**
   * Persists a new Risk Decision row in Supabase risk_decisions table (with in-memory fallback)
   */
  async createRiskDecision(decisionData) {
    const newDecision = createRiskDecisionEntity(decisionData);
    if (!newDecision.risk_decision_id) {
      newDecision.risk_decision_id = `RSK-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).substring(2, 6).toUpperCase()}`;
    }

    inMemoryRiskDecisions.set(newDecision.risk_decision_id, newDecision);

    try {
      const { data, error } = await supabase
        .from('risk_decisions')
        .insert([{
          risk_decision_id: newDecision.risk_decision_id,
          transaction_id: newDecision.transaction_id,
          user_id: newDecision.user_id,
          risk_score: newDecision.risk_score,
          risk_level: newDecision.risk_level,
          decision: newDecision.decision,
          risk_factors: newDecision.risk_factors,
          baseline_snapshot: newDecision.baseline_snapshot,
          created_at: newDecision.created_at
        }])
        .select()
        .single();

      if (error) {
        console.warn('Supabase createRiskDecision warning (using in-memory fallback):', error.message);
        return newDecision;
      }

      return data || newDecision;
    } catch (err) {
      console.warn('Supabase createRiskDecision exception (using in-memory fallback):', err.message);
      return newDecision;
    }
  },

  /**
   * Retrieves risk decisions for a given user ID (newest first)
   */
  async getRiskDecisionsForUser(userId) {
    if (!userId) return [];

    let supabaseData = [];
    try {
      const { data, error } = await supabase
        .from('risk_decisions')
        .select('*')
        .eq('user_id', userId)
        .order('created_at', { ascending: false });

      if (!error && data) {
        supabaseData = data;
      }
    } catch (e) {}

    const memoryData = Array.from(inMemoryRiskDecisions.values())
      .filter(r => r.user_id === userId);

    const mergedMap = new Map();
    [...memoryData, ...supabaseData].forEach(item => {
      mergedMap.set(item.risk_decision_id, item);
    });

    return Array.from(mergedMap.values()).sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  },

  /**
   * Finds a risk decision by transaction_id
   */
  async getRiskDecisionByTransactionId(transactionId) {
    if (!transactionId) return null;

    try {
      const { data, error } = await supabase
        .from('risk_decisions')
        .select('*')
        .eq('transaction_id', transactionId)
        .maybeSingle();

      if (!error && data) return data;
    } catch (e) {}

    return Array.from(inMemoryRiskDecisions.values()).find(r => r.transaction_id === transactionId) || null;
  }
};
