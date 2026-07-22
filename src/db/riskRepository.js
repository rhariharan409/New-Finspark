/**
 * Risk Repository (Supabase PostgreSQL Integration)
 * Data Access Layer executing queries against the Supabase risk_decisions table.
 */

import { supabase } from './supabaseClient.js';
import { createRiskDecisionEntity } from '../models/riskModel.js';

export const riskRepository = {
  /**
   * Persists a new Risk Decision row in Supabase risk_decisions table
   */
  async createRiskDecision(decisionData) {
    const newDecision = createRiskDecisionEntity(decisionData);

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
      console.error('Supabase createRiskDecision error:', error.message);
      throw new Error(`Failed to create risk decision record: ${error.message}`);
    }

    return data || newDecision;
  },

  /**
   * Retrieves risk decisions for a given user ID (newest first)
   */
  async getRiskDecisionsForUser(userId) {
    if (!userId) return [];

    const { data, error } = await supabase
      .from('risk_decisions')
      .select('*')
      .eq('user_id', userId)
      .order('created_at', { ascending: false });

    if (error) {
      console.error('Supabase getRiskDecisionsForUser error:', error.message);
      throw new Error(`Failed to retrieve risk decisions: ${error.message}`);
    }

    return data || [];
  },

  /**
   * Finds a risk decision by transaction_id
   */
  async getRiskDecisionByTransactionId(transactionId) {
    if (!transactionId) return null;

    const { data, error } = await supabase
      .from('risk_decisions')
      .select('*')
      .eq('transaction_id', transactionId)
      .maybeSingle();

    if (error && error.code !== 'PGRST116') {
      console.error('Supabase getRiskDecisionByTransactionId error:', error.message);
    }

    return data || null;
  }
};
