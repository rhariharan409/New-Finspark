import { supabase } from '../../db/supabaseClient.js';
import { userRepository } from '../../db/userRepository.js';
import { transactionRepository } from '../../db/transactionRepository.js';
import { telemetryRepository } from '../../db/telemetryRepository.js';

export const signalCollector = {
  /**
   * Gathers sender's session and telemetry timeline events.
   */
  async getSenderObservedEvents(senderAccountId) {
    try {
      const senderUser = await userRepository.findUserByAccountId(senderAccountId);
      if (!senderUser) return [];

      // 1. Fetch telemetry events
      const events = await telemetryRepository.getEventsForUser(senderUser.user_id);
      
      // 2. Fetch risk decisions to get elevated risk markers
      const { data: riskDecisions } = await supabase
        .from('risk_decisions')
        .select('*')
        .eq('user_id', senderUser.user_id)
        .order('created_at', { ascending: false });

      // Combine and map to structured sequence format
      const combined = [];

      // Map telemetry
      events.forEach(e => {
        combined.push({
          event_type: e.event_type,
          timestamp: e.event_timestamp || e.created_at,
          description: e.metadata?.description || `Telemetry event ${e.event_type}`,
          metadata: e.metadata || {}
        });
      });

      // Map risk decisions
      (riskDecisions || []).forEach(r => {
        combined.push({
          event_type: 'risk_evaluation',
          timestamp: r.created_at,
          risk_score: r.risk_score,
          description: `Risk decision: ${r.decision}. Score: ${r.risk_score}`,
          metadata: { decision: r.decision, risk_level: r.risk_level }
        });
      });

      // Sort chronological ascending (first to last)
      return combined.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

    } catch (err) {
      console.error('[MMIE] getSenderObservedEvents error:', err.message);
      return [];
    }
  },

  /**
   * Retrieves receiver's standing posture score.
   */
  async getReceiverPosture(receiverAccountId) {
    try {
      const { data, error } = await supabase
        .from('mule_posture')
        .select('*')
        .eq('account_id', receiverAccountId)
        .maybeSingle();

      if (error && error.code !== 'PGRST116') {
        console.error('[MMIE] getReceiverPosture db error:', error.message);
      }

      return data || {
        account_id: receiverAccountId,
        posture_score: 0.0,
        hawkes_intensity: 0.0,
        hawkes_last_updated: null,
        retention_half_life_seconds: null,
        unique_senders_24h: 0,
        inflow_count_24h: 0,
        community_id: 'default',
        graph_reputation: 0.0
      };
    } catch (err) {
      console.error('[MMIE] getReceiverPosture error:', err.message);
      return null;
    }
  },

  /**
   * Counts unique senders and total transfers received in the last 24 hours.
   */
  async getReceiverInflowStats24h(receiverAccountId) {
    try {
      const receiverUser = await userRepository.findUserByAccountId(receiverAccountId);
      if (!receiverUser) return { uniqueSenders: 0, inflowCount: 0 };

      const timeLimit = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

      const { data: txns, error } = await supabase
        .from('transactions')
        .select('sender_user_id')
        .eq('receiver_user_id', receiverUser.user_id)
        .gte('transaction_timestamp', timeLimit);

      if (error) throw error;

      if (!txns || txns.length === 0) {
        return { uniqueSenders: 0, inflowCount: 0 };
      }

      // We need unique senders (their accounts)
      const senderUserIds = Array.from(new Set(txns.map(t => t.sender_user_id)));
      
      return {
        uniqueSenders: senderUserIds.length,
        inflowCount: txns.length
      };

    } catch (err) {
      console.error('[MMIE] getReceiverInflowStats24h error:', err.message);
      return { uniqueSenders: 0, inflowCount: 0 };
    }
  },

  /**
   * Retrieves outflow transactions of the receiver after a specific inflow timestamp
   */
  async getReceiverOutflowsAfter(receiverAccountId, inflowTimestampIso) {
    try {
      const receiverUser = await userRepository.findUserByAccountId(receiverAccountId);
      if (!receiverUser) return [];

      const { data: txns, error } = await supabase
        .from('transactions')
        .select('amount, transaction_timestamp, created_at')
        .eq('sender_user_id', receiverUser.user_id)
        .gte('transaction_timestamp', inflowTimestampIso)
        .order('transaction_timestamp', { ascending: true });

      if (error) throw error;

      return (txns || []).map(t => ({
        amount: parseFloat(t.amount) || 0.0,
        timestampMs: new Date(t.transaction_timestamp || t.created_at).getTime()
      }));

    } catch (err) {
      console.error('[MMIE] getReceiverOutflowsAfter error:', err.message);
      return [];
    }
  }
};
