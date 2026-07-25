import { supabase } from '../../db/supabaseClient.js';
import { signalCollector } from './signalCollector.js';
import { updateHawkesIntensity } from './hawkesEngine.js';
import { computeHalfLife } from './retentionHalfLife.js';
import { scoreSequence } from './sequenceMatcher.js';
import { fuseMuleConfidence } from './bayesianFusion.js';
import { buildEvidenceChain } from './explainability.js';
import { graphEngine } from './graphEngine.js';
import { userRepository } from '../../db/userRepository.js';

// Configurable Decision Thresholds
export const DECISION_THRESHOLDS = {
  BLOCK: 90,
  HOLD: 70,
  STEP_UP: 40
};

/**
 * Maps confidence score to standard decision label.
 * @param {number} confidence 
 * @returns {string}
 */
export function getMuleDecision(confidence) {
  if (confidence >= DECISION_THRESHOLDS.BLOCK) return 'block';
  if (confidence >= DECISION_THRESHOLDS.HOLD) return 'hold';
  if (confidence >= DECISION_THRESHOLDS.STEP_UP) return 'step_up';
  return 'allow';
}

/**
 * Computes Likelihood Ratio for receiver posture.
 */
function calculateReceiverLR(hawkes, halfLife) {
  let lr = 1.0;
  // Hawkes factor: center at 2.0
  const hawkesFactor = 8.0 / (1.0 + Math.exp(-(hawkes - 2.0)));
  lr += hawkesFactor;

  // Half-life factor: center at 300s (5m), grows larger as halfLife gets smaller
  if (halfLife !== null && halfLife > 0) {
    const halfLifeFactor = 6.0 / (1.0 + Math.exp((halfLife - 300) / 100));
    lr += halfLifeFactor;
  }
  return lr;
}

/**
 * Computes Likelihood Ratio for graph network reputation.
 */
function calculateGraphLR(pagerank, communityId) {
  let lr = 1.0;
  // PageRank factor: propogates risk directly from reported fraud seeds
  if (pagerank > 0) {
    lr += pagerank * 2000;
  }
  return lr;
}

/**
 * Computes Likelihood Ratio for sequence matching.
 */
function calculateSequenceLR(matchRatio) {
  // Center at 0.5 match ratio
  return 1.0 + 12.0 / (1.0 + Math.exp(-8.0 * (matchRatio - 0.5)));
}

export const muleService = {
  /**
   * Performs synchronous transaction-time scoring for money mule risk.
   * Updates receiver posture metrics and records the assessment in database.
   * 
   * @param {object} params
   * @param {string} params.transactionId
   * @param {string} params.senderAccountId
   * @param {string} params.receiverAccountId
   * @returns {Promise<object>}
   */
  async assessTransaction({ transactionId, senderAccountId, receiverAccountId }) {
    try {
      console.log(`[MMIE] Assessing transaction ${transactionId} (Sender: ${senderAccountId} -> Receiver: ${receiverAccountId})...`);

      // 1. Update shared attributes in entity graph first (beneficiary link, shared IPs, etc.)
      await graphEngine.linkSharedAttributes(senderAccountId, receiverAccountId);

      // 2. Fetch current receiver posture (contains latest PageRank & Louvain ID)
      const currentPosture = await signalCollector.getReceiverPosture(receiverAccountId);

      // 3. Update Hawkes Intensity & Inflow metrics for Receiver
      const now = Date.now();
      const prevHawkes = parseFloat(currentPosture?.hawkes_intensity) || 0.0;
      const prevHawkesTime = currentPosture?.hawkes_last_updated ? new Date(currentPosture.hawkes_last_updated).getTime() : now;
      const newHawkes = updateHawkesIntensity(prevHawkes, prevHawkesTime, now);

      const inflowStats = await signalCollector.getReceiverInflowStats24h(receiverAccountId);

      // 4. Calculate retention half-life of receiver
      let newHalfLife = currentPosture?.retention_half_life_seconds || null;
      const receiverUser = await userRepository.findUserByAccountId(receiverAccountId);
      if (receiverUser) {
        // Fetch last 5 inflows of receiver to check drain status
        const { data: recentInflows } = await supabase
          .from('transactions')
          .select('amount, transaction_timestamp, created_at')
          .eq('receiver_user_id', receiverUser.user_id)
          .order('transaction_timestamp', { ascending: false })
          .limit(5);

        if (recentInflows && recentInflows.length > 0) {
          const halfLifes = [];
          for (const inflow of recentInflows) {
            const inflowAmt = parseFloat(inflow.amount) || 0.0;
            const inflowTimeIso = inflow.transaction_timestamp || inflow.created_at;
            const inflowTimeMs = new Date(inflowTimeIso).getTime();
            const subsequentOutflows = await signalCollector.getReceiverOutflowsAfter(receiverAccountId, inflowTimeIso);
            const hl = computeHalfLife(inflowAmt, inflowTimeMs, subsequentOutflows);
            if (hl !== null) {
              halfLifes.push(hl);
            }
          }
          if (halfLifes.length > 0) {
            newHalfLife = halfLifes[0]; // Take the latest calculated one
          }
        }
      }

      // 5. Update receiver posture table with fresh Hawkes & stats
      const { data: updatedPosture, error: postureErr } = await supabase
        .from('mule_posture')
        .upsert({
          account_id: receiverAccountId,
          hawkes_intensity: newHawkes,
          hawkes_last_updated: new Date(now).toISOString(),
          retention_half_life_seconds: newHalfLife,
          unique_senders_24h: inflowStats.uniqueSenders,
          inflow_count_24h: inflowStats.inflowCount,
          last_updated: new Date(now).toISOString()
        }, { onConflict: 'account_id' })
        .select()
        .single();

      if (postureErr) {
        console.error('[MMIE] Error updating receiver posture:', postureErr.message);
      }

      const activePosture = updatedPosture || currentPosture;

      // 6. Pull attack sequence timeline events for the sender
      const observedEvents = await signalCollector.getSenderObservedEvents(senderAccountId);
      const sequenceMatchRatio = scoreSequence(observedEvents);

      // 7. Compute independent Likelihood Ratios
      const receiverLR = calculateReceiverLR(
        parseFloat(activePosture?.hawkes_intensity) || 0.0,
        activePosture?.retention_half_life_seconds
      );

      const graphLR = calculateGraphLR(
        parseFloat(activePosture?.graph_reputation) || 0.0,
        activePosture?.community_id
      );

      const sequenceLR = calculateSequenceLR(sequenceMatchRatio);

      // 8. Execute Bayesian Likelihood-Ratio Fusion
      const confidence = fuseMuleConfidence({
        receiverLR,
        graphLR,
        sequenceLR
      });

      // 9. Format Evidence Chain with exact normalized contribution percentages
      const evidence = buildEvidenceChain(confidence, {
        receiverLR,
        graphLR,
        sequenceLR,
        factors: {
          hawkesIntensity: parseFloat(activePosture?.hawkes_intensity) || 0.0,
          halfLife: activePosture?.retention_half_life_seconds,
          pageRank: parseFloat(activePosture?.graph_reputation) || 0.0,
          communityId: activePosture?.community_id,
          inSuspiciousCommunity: activePosture?.community_id && activePosture.community_id !== 'default',
          sequenceMatchRatio
        }
      });

      const decision = getMuleDecision(confidence);

      // Update receiver standing posture_score in mule_posture
      await supabase
        .from('mule_posture')
        .update({ posture_score: confidence, last_updated: new Date().toISOString() })
        .eq('account_id', receiverAccountId);

      // 10. Persist Mule Assessment row to Supabase
      const { data: savedAssessment, error: assessErr } = await supabase
        .from('mule_assessments')
        .insert([{
          transaction_id: transactionId,
          sender_account_id: senderAccountId,
          receiver_account_id: receiverAccountId,
          mule_confidence: confidence,
          evidence,
          decision
        }])
        .select()
        .single();

      if (assessErr) {
        console.error('[MMIE] Error saving assessment:', assessErr.message);
      }

      // Normalize evidence array if read back as string from Supabase client driver
      let normalizedEvidence = savedAssessment?.evidence || evidence;
      if (typeof normalizedEvidence === 'string') {
        try {
          normalizedEvidence = JSON.parse(normalizedEvidence);
        } catch (parseErr) {
          console.error('[MMIE] Failed to parse evidence string:', parseErr.message);
          normalizedEvidence = [];
        }
      }

      console.log(`[MMIE] Assessment complete. Confidence: ${confidence}%, Decision: ${decision}`);

      return {
        muleConfidence: confidence,
        decision,
        evidence: normalizedEvidence,
        assessmentId: savedAssessment?.id || null
      };

    } catch (err) {
      console.error('[MMIE] assessTransaction failed:', err.message);
      // Fail-safe to avoid blocking transactions if a db exception occurs
      return {
        muleConfidence: 10,
        decision: 'allow',
        evidence: [{ signal: 'error_fallback', contributionPct: 10, description: 'Evaluation fell back to default parameters.' }]
      };
    }
  }
};
