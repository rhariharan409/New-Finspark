/**
 * Transaction Repository (Supabase PostgreSQL Integration)
 * Data Access Layer executing queries against the Supabase transactions table.
 */

import { supabase } from './supabaseClient.js';
import { createTransactionEntity } from '../models/transactionModel.js';

export const transactionRepository = {
  /**
   * Persists a new Transaction row in Supabase transactions table
   */
  async createTransaction(transactionData) {
    const newTxn = createTransactionEntity(transactionData);

    const { data, error } = await supabase
      .from('transactions')
      .insert([{
        transaction_id: newTxn.transaction_id,
        sender_user_id: newTxn.sender_user_id,
        receiver_user_id: newTxn.receiver_user_id,
        amount: newTxn.amount,
        currency: newTxn.currency,
        transaction_type: newTxn.transaction_type,
        transaction_status: newTxn.transaction_status,
        transaction_timestamp: newTxn.transaction_timestamp,
        description: newTxn.description,
        created_at: newTxn.created_at
      }])
      .select()
      .single();

    if (error) {
      console.error('Supabase createTransaction error:', error.message);
      throw new Error(`Failed to create transaction record: ${error.message}`);
    }

    const resultTxn = data || newTxn;
    if (newTxn.session_id) {
      resultTxn.session_id = newTxn.session_id;
    }
    return resultTxn;
  },

  /**
   * Retrieves transactions created during a specific session ID using telemetry linkage and session time-window aggregation
   */
  async getTransactionsForSession(sessionId) {
    if (!sessionId) return [];

    // 1. Query transaction IDs linked to this session_id in telemetry_events
    const { data: telemetryData } = await supabase
      .from('telemetry_events')
      .select('transaction_id')
      .eq('session_id', sessionId)
      .not('transaction_id', 'is', null);

    const txIdsFromTelemetry = (telemetryData || []).map(t => t.transaction_id).filter(Boolean);

    // 2. Retrieve session record to fallback on time-window query if needed
    const { data: sessionData } = await supabase
      .from('sessions')
      .select('*')
      .eq('session_id', sessionId)
      .maybeSingle();

    if (txIdsFromTelemetry.length > 0) {
      const { data: txns, error: txErr } = await supabase
        .from('transactions')
        .select('*')
        .in('transaction_id', txIdsFromTelemetry)
        .order('transaction_timestamp', { ascending: true });

      if (!txErr && txns && txns.length > 0) {
        return txns.map(t => ({ ...t, session_id: sessionId }));
      }
    }

    // 3. Fallback: Query by sender_user_id and session login_time / logout_time window
    if (sessionData) {
      let query = supabase
        .from('transactions')
        .select('*')
        .eq('sender_user_id', sessionData.user_id)
        .gte('transaction_timestamp', sessionData.login_time);

      if (sessionData.logout_time) {
        query = query.lte('transaction_timestamp', sessionData.logout_time);
      }

      const { data: timeWindowTxns } = await query.order('transaction_timestamp', { ascending: true });
      return (timeWindowTxns || []).map(t => ({ ...t, session_id: sessionId }));
    }

    return [];
  },

  /**
   * Retrieves transaction records related to a user (as sender or receiver) ordered newest first
   */
  async getTransactionsForUser(userId) {
    if (!userId) return [];

    const { data, error } = await supabase
      .from('transactions')
      .select('*')
      .or(`sender_user_id.eq.${userId},receiver_user_id.eq.${userId}`)
      .order('transaction_timestamp', { ascending: false });

    if (error) {
      console.error('Supabase getTransactionsForUser error:', error.message);
      throw new Error(`Failed to retrieve transaction history: ${error.message}`);
    }

    return data || [];
  },

  /**
   * Finds a transaction row by transaction_id
   */
  async getTransactionById(transactionId) {
    if (!transactionId) return null;

    const { data, error } = await supabase
      .from('transactions')
      .select('*')
      .eq('transaction_id', transactionId)
      .maybeSingle();

    if (error && error.code !== 'PGRST116') {
      console.error('Supabase getTransactionById error:', error.message);
    }

    return data || null;
  }
};
