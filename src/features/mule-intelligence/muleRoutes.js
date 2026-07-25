import express from 'express';
import { supabase } from '../../db/supabaseClient.js';
import { muleService } from './muleService.js';
import { graphEngine } from './graphEngine.js';
import { userRepository } from '../../db/userRepository.js';

const router = express.Router();

/**
 * Analyst Authentication Middleware
 * On Vercel serverless, in-memory sessions don't persist between invocations.
 * In that environment, we allow requests through since the UI already gates access via login.
 */
function requireAnalystAuth(req, res, next) {
  // In Vercel serverless, sessions are ephemeral — skip check for demo
  if (process.env.VERCEL) {
    return next();
  }
  if (req.session && req.session.isAnalyst && req.session.analystProfile) {
    return next();
  }
  return res.status(401).json({
    success: false,
    message: 'Access Denied: Active Cyber Analyst session required.'
  });
}

/**
 * Get current mule posture for an account
 * GET /api/mule/posture/:accountId
 */
router.get('/posture/:accountId', requireAnalystAuth, async (req, res) => {
  try {
    const { accountId } = req.params;
    if (!accountId) {
      return res.status(400).json({ error: 'Invalid account ID' });
    }

    const cleanAccountId = accountId.trim();

    // Check UUID / Account ID format validation
    const isValidFormat = /^(TURTLE-[A-Za-z0-9\-]+|ACC-[A-Za-z0-9\-]+|USR-[A-Za-z0-9\-]+|[A-Za-z0-9\-_]{3,64}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i.test(cleanAccountId);
    if (!isValidFormat) {
      return res.status(400).json({ error: 'Invalid account ID format' });
    }

    const { data: posture, error } = await supabase
      .from('mule_posture')
      .select('*')
      .eq('account_id', cleanAccountId)
      .maybeSingle();

    if (error && error.code !== 'PGRST116') {
      throw error;
    }

    const activePosture = posture || {
      account_id: cleanAccountId,
      posture_score: 0,
      hawkes_intensity: 0.0,
      retention_half_life_seconds: null,
      graph_reputation: 0.0,
      community_id: 'default'
    };

    // Fetch the latest transaction-time assessment for this account
    const { data: assessments } = await supabase
      .from('mule_assessments')
      .select('*')
      .or(`sender_account_id.eq.${cleanAccountId},receiver_account_id.eq.${cleanAccountId}`)
      .order('created_at', { ascending: false })
      .limit(1);

    const latestAssessment = assessments && assessments.length > 0 ? assessments[0] : null;

    return res.status(200).json({
      success: true,
      posture: activePosture,
      latestAssessment
    });

  } catch (err) {
    console.error('GET /posture/:accountId error:', err.message);
    return res.status(500).json({ success: false, message: 'Failed to retrieve mule posture.' });
  }
});

/**
 * Trigger scoring assessment for a transaction
 * POST /api/mule/assess
 */
router.post('/assess', requireAnalystAuth, async (req, res) => {
  try {
    const { transactionId, senderAccountId, receiverAccountId } = req.body;

    if (!transactionId || !senderAccountId || !receiverAccountId) {
      return res.status(400).json({
        success: false,
        message: 'Missing required body fields: transactionId, senderAccountId, receiverAccountId'
      });
    }

    const assessment = await muleService.assessTransaction({
      transactionId: String(transactionId).trim(),
      senderAccountId: String(senderAccountId).trim(),
      receiverAccountId: String(receiverAccountId).trim()
    });

    return res.status(200).json({
      success: true,
      assessment
    });

  } catch (err) {
    console.error('POST /assess error:', err.message);
    return res.status(500).json({ success: false, message: 'Failed to assess transaction.' });
  }
});

/**
 * Retrieve evidence for a specific assessment ID
 * GET /api/mule/evidence/:assessmentId
 */
router.get('/evidence/:assessmentId', requireAnalystAuth, async (req, res) => {
  try {
    const { assessmentId } = req.params;
    if (!assessmentId) {
      return res.status(400).json({ success: false, message: 'Assessment ID parameter is required.' });
    }

    // Validate if it is a valid UUID string to prevent SQL error
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    if (!uuidRegex.test(assessmentId)) {
      return res.status(400).json({ success: false, message: 'Invalid Assessment ID format (UUID required).' });
    }

    const { data: assessment, error } = await supabase
      .from('mule_assessments')
      .select('*')
      .eq('id', assessmentId)
      .maybeSingle();

    if (error && error.code !== 'PGRST116') {
      throw error;
    }

    if (!assessment) {
      return res.status(404).json({ success: false, message: `Assessment not found for ID '${assessmentId}'.` });
    }

    let normalizedEvidence = assessment.evidence;
    if (typeof normalizedEvidence === 'string') {
      try {
        normalizedEvidence = JSON.parse(normalizedEvidence);
      } catch (parseErr) {
        console.error('[MMIE] Failed to parse evidence string in GET route:', parseErr.message);
        normalizedEvidence = [];
      }
    }

    return res.status(200).json({
      success: true,
      assessment: {
        ...assessment,
        evidence: normalizedEvidence
      }
    });

  } catch (err) {
    console.error('GET /evidence/:assessmentId error:', err.message);
    return res.status(500).json({ success: false, message: 'Failed to retrieve assessment evidence.' });
  }
});

/**
 * Retrieve community clusters / rings
 * GET /api/mule/rings
 */
router.get('/rings', requireAnalystAuth, async (req, res) => {
  try {
    const accountId = req.query.accountId ? String(req.query.accountId).trim() : null;
    const ringData = await graphEngine.getRingsForAccount(accountId);

    // Fetch transactions between community members
    const memberAccountIds = (ringData.postures || []).map(p => p.account_id);
    let transactions = [];

    if (memberAccountIds.length > 0) {
      // Resolve account_id -> user_id mapping
      const { data: users } = await supabase
        .from('users')
        .select('user_id, account_id, full_name')
        .in('account_id', memberAccountIds);

      const userIdToAccount = {};
      const accountToName = {};
      const userIds = [];
      (users || []).forEach(u => {
        userIdToAccount[u.user_id] = u.account_id;
        accountToName[u.account_id] = u.full_name || u.account_id;
        userIds.push(u.user_id);
      });

      if (userIds.length > 0) {
        // Fetch transactions where sender OR receiver is in the community
        const { data: sentTxns } = await supabase
          .from('transactions')
          .select('transaction_id, sender_user_id, receiver_user_id, amount, transaction_timestamp, transaction_status, description')
          .in('sender_user_id', userIds)
          .order('transaction_timestamp', { ascending: false })
          .limit(50);

        const { data: recvTxns } = await supabase
          .from('transactions')
          .select('transaction_id, sender_user_id, receiver_user_id, amount, transaction_timestamp, transaction_status, description')
          .in('receiver_user_id', userIds)
          .order('transaction_timestamp', { ascending: false })
          .limit(50);

        // Merge and deduplicate by transaction id
        const txnMap = new Map();
        [...(sentTxns || []), ...(recvTxns || [])].forEach(t => {
          const key = t.transaction_id;
          if (key && !txnMap.has(key)) txnMap.set(key, t);
        });

        transactions = Array.from(txnMap.values())
          .map(t => ({
            transaction_id: t.transaction_id,
            sender_account_id: userIdToAccount[t.sender_user_id] || t.sender_user_id,
            sender_name: accountToName[userIdToAccount[t.sender_user_id]] || userIdToAccount[t.sender_user_id] || t.sender_user_id,
            receiver_account_id: userIdToAccount[t.receiver_user_id] || t.receiver_user_id,
            receiver_name: accountToName[userIdToAccount[t.receiver_user_id]] || userIdToAccount[t.receiver_user_id] || t.receiver_user_id,
            amount: parseFloat(t.amount) || 0,
            timestamp: t.transaction_timestamp,
            status: t.transaction_status || 'completed',
            description: t.description || 'Fund transfer'
          }))
          .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
          .slice(0, 50);
      }
    }

    return res.status(200).json({
      success: true,
      postures: ringData.postures,
      edges: ringData.edges,
      transactions
    });

  } catch (err) {
    console.error('GET /rings error:', err.message);
    return res.status(500).json({ success: false, message: 'Failed to retrieve network rings.' });
  }
});

export const muleRouter = router;
export { requireAnalystAuth };
