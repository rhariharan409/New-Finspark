import express from 'express';
import { supabase } from '../../db/supabaseClient.js';
import { muleService } from './muleService.js';
import { graphEngine } from './graphEngine.js';

const router = express.Router();

/**
 * Analyst Authentication Middleware
 */
function requireAnalystAuth(req, res, next) {
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
      return res.status(400).json({ success: false, message: 'Account ID parameter is required.' });
    }

    const { data: posture, error } = await supabase
      .from('mule_posture')
      .select('*')
      .eq('account_id', accountId.trim())
      .maybeSingle();

    if (error && error.code !== 'PGRST116') {
      throw error;
    }

    // Fetch the latest transaction-time assessment for this account
    const { data: assessments } = await supabase
      .from('mule_assessments')
      .select('*')
      .or(`sender_account_id.eq.${accountId.trim()},receiver_account_id.eq.${accountId.trim()}`)
      .order('created_at', { ascending: false })
      .limit(1);

    const latestAssessment = assessments && assessments.length > 0 ? assessments[0] : null;

    return res.status(200).json({
      success: true,
      posture: posture || {
        account_id: accountId,
        posture_score: 0,
        hawkes_intensity: 0,
        hawkes_last_updated: null,
        retention_half_life_seconds: null,
        unique_senders_24h: 0,
        inflow_count_24h: 0,
        community_id: 'default',
        graph_reputation: 0,
        last_updated: new Date().toISOString()
      },
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

    return res.status(200).json({
      success: true,
      assessment
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

    return res.status(200).json({
      success: true,
      postures: ringData.postures,
      edges: ringData.edges
    });

  } catch (err) {
    console.error('GET /rings error:', err.message);
    return res.status(500).json({ success: false, message: 'Failed to retrieve network rings.' });
  }
});

export const muleRouter = router;
export { requireAnalystAuth };
