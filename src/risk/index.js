/**
 * Risk Decision Engine API Router
 * Implements REST endpoints for analyzing transaction risk and querying risk decision history.
 */

import express from 'express';
import { riskAnalysisService } from '../services/riskAnalysisService.js';
import { sessionModule } from '../session/index.js';

const router = express.Router();

/**
 * Analyze Transaction Risk API
 * POST /api/risk/analyze
 */
router.post('/analyze', sessionModule.requireAuth, async (req, res) => {
  try {
    const userId = req.session.userId;
    const { transaction_id } = req.body;

    if (!transaction_id) {
      return res.status(400).json({
        success: false,
        message: 'transaction_id is required for risk analysis.'
      });
    }

    const riskDecision = await riskAnalysisService.analyzeTransactionRisk({
      transactionId: transaction_id,
      userId,
      sessionRiskContext: req.sessionRiskContext
    });

    return res.status(200).json({
      success: true,
      message: 'Risk analysis completed successfully.',
      risk_decision: riskDecision
    });

  } catch (error) {
    console.error('Risk Analyze Error:', error.message);
    const isUnauthorized = error.message.includes('Unauthorized') || error.message.includes('own transactions');
    return res.status(isUnauthorized ? 403 : 400).json({
      success: false,
      message: error.message || 'Failed to complete risk analysis.'
    });
  }
});

/**
 * Get User Risk Decisions History API
 * GET /api/risk/decisions
 */
router.get('/decisions', sessionModule.requireAuth, async (req, res) => {
  try {
    const userId = req.session.userId;
    const decisions = await riskAnalysisService.getUserRiskDecisions(userId);

    return res.status(200).json({
      success: true,
      count: decisions.length,
      decisions
    });

  } catch (error) {
    console.error('Risk Decisions GET Error:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Failed to retrieve risk decisions history.'
    });
  }
});

export const riskModule = {
  name: 'risk',
  router
};
