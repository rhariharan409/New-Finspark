/**
 * Banking & Transaction API Router with Internal Risk Engine Execution
 * Implements REST endpoints for transaction creation and history queries for normal banking users.
 * STRICTLY ISOLATED: Internal risk scores, decision reasoning, and telemetry details are stored in Supabase for Cyber Analysts but NEVER exposed to normal users.
 */

import express from 'express';
import { transactionService } from '../services/transactionService.js';
import { telemetryService } from '../services/telemetryService.js';
import { riskAnalysisService } from '../services/riskAnalysisService.js';
import { sessionModule } from '../session/index.js';

const router = express.Router();

/**
 * Create Transaction API
 * POST /api/transactions
 */
router.post('/', sessionModule.requireAuth, async (req, res) => {
  const senderUserId = req.session.userId;
  const sessionId = req.session.sessionId || null;
  const clientDetails = telemetryService.extractClientDetails(req);
  const { receiver_user_id, receiver_identifier, amount, transaction_type, description } = req.body;
  const targetReceiver = receiver_identifier || receiver_user_id;

  try {
    if (!targetReceiver) {
      throw new Error('Receiver account or identifier is required.');
    }

    // 1. Execute Transaction linked to authenticated active session
    const transaction = await transactionService.createTransaction({
      senderUserId,
      sessionId,
      receiverIdentifier: targetReceiver,
      amount,
      transactionType: transaction_type,
      description
    });

    // 2. Record telemetry event in database (internal)
    try {
      await telemetryService.recordTelemetryEvent({
        userId: senderUserId,
        sessionId,
        transactionId: transaction.transaction_id,
        eventType: 'transaction_created',
        ipAddress: clientDetails.ipAddress,
        deviceType: clientDetails.deviceType,
        metadata: {
          receiver_user_id: transaction.receiver_user_id,
          amount: transaction.amount,
          currency: transaction.currency,
          description: transaction.description
        }
      });
    } catch (telemetryErr) {
      console.error('Telemetry transaction_created Error:', telemetryErr.message);
    }

    // 3. Automatically trigger Internal Risk Engine & store risk decision in Supabase for Cyber Analysts
    const riskDecision = await riskAnalysisService.analyzeTransactionRisk({
      transactionId: transaction.transaction_id,
      userId: senderUserId
    });

    // 4. CUSTOMER-SAFE RESPONSE MAPPING (Zero internal risk metrics exposed)
    const decisionType = riskDecision ? (riskDecision.decision || 'ALLOW').toUpperCase() : 'ALLOW';
    const riskLevel = riskDecision ? (riskDecision.risk_level || 'LOW').toUpperCase() : 'LOW';

    let userMessage = "Transaction Successful";

    if (decisionType === 'BLOCK' || riskLevel === 'CRITICAL') {
      return res.status(400).json({
        success: false,
        message: "Transaction could not be completed at this time. Please verify your information or contact support."
      });
    } else if (decisionType === 'REVIEW' || riskLevel === 'HIGH') {
      userMessage = "Transaction Under Review. Additional verification may be required for your security.";
    } else if (decisionType === 'MONITOR' || riskLevel === 'MEDIUM') {
      userMessage = "Transaction Successful. We are monitoring this transaction for your security.";
    }

    // Return sanitized transaction object to normal user
    const safeTransaction = {
      transaction_id: transaction.transaction_id,
      receiver_identifier: targetReceiver,
      amount: parseFloat(transaction.amount),
      currency: transaction.currency || 'INR',
      transaction_status: decisionType === 'REVIEW' ? 'pending_review' : 'completed',
      transaction_timestamp: transaction.transaction_timestamp || transaction.created_at,
      description: transaction.description
    };

    return res.status(201).json({
      success: true,
      message: userMessage,
      transaction: safeTransaction
    });

  } catch (error) {
    console.error('Transaction POST Error:', error.message);

    return res.status(400).json({
      success: false,
      message: error.message || 'Transaction could not be completed at this time. Please verify your information or contact support.'
    });
  }
});

/**
 * Get User Transactions History API
 * GET /api/transactions
 */
router.get('/', sessionModule.requireAuth, async (req, res) => {
  try {
    const userId = req.session.userId;
    const transactions = await transactionService.getUserTransactions(userId);

    // Return clean user-facing banking transaction history
    const safeHistory = transactions.map(t => ({
      transaction_id: t.transaction_id,
      type: t.sender_user_id === userId ? 'SENT' : 'RECEIVED',
      counterparty: t.sender_user_id === userId ? t.receiver_user_id : t.sender_user_id,
      amount: parseFloat(t.amount),
      currency: t.currency || 'INR',
      status: t.transaction_status,
      timestamp: t.transaction_timestamp || t.created_at,
      description: t.description
    }));

    return res.status(200).json({
      success: true,
      count: safeHistory.length,
      transactions: safeHistory
    });

  } catch (error) {
    console.error('Transaction GET Error:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Failed to retrieve transactions history.'
    });
  }
});

/**
 * Initiate ATO Controlled Transaction Simulation API (from Hacker Section)
 * POST /api/transactions/initiate-ato-transaction
 */
router.post('/initiate-ato-transaction', async (req, res) => {
  try {
    const { sessionId, receiverIdentifier, amount, description } = req.body;
    const { atoVerificationService } = await import('../services/atoVerificationService.js');
    const result = await atoVerificationService.initiateAtoTransaction({
      sessionId,
      receiverIdentifier,
      amount,
      description
    });
    return res.status(200).json(result);
  } catch (err) {
    return res.status(400).json({ success: false, message: err.message });
  }
});

/**
 * Initiator (Hacker Side) Confirms Intent (OK, CONFIRM INTENT or CANCEL TRANSACTION)
 * POST /api/transactions/confirm-initiator-intent
 */
router.post('/confirm-initiator-intent', async (req, res) => {
  try {
    const { requestId, intentAction } = req.body;
    const { atoVerificationService } = await import('../services/atoVerificationService.js');
    const result = await atoVerificationService.confirmInitiatorIntent({
      requestId,
      intentAction
    });
    return res.status(200).json(result);
  } catch (err) {
    return res.status(400).json({ success: false, message: err.message });
  }
});

/**
 * Check Pending ATO Approvals for User Dashboard
 * GET /api/transactions/pending-ato-approvals
 */
router.get('/pending-ato-approvals', async (req, res) => {
  try {
    const userId = req.session?.userId;
    if (!userId) {
      return res.status(200).json({ success: true, pendingRequests: [] });
    }
    const { atoVerificationService } = await import('../services/atoVerificationService.js');
    await atoVerificationService.checkAndExpirePendingRequests();

    const { atoRequestRepository } = await import('../db/atoRequestRepository.js');
    const pending = await atoRequestRepository.getPendingRequestsForUser(userId);

    return res.status(200).json({
      success: true,
      pendingRequests: pending
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

/**
 * Legitimate User Responds to Approval Request (YES, APPROVE / NO, BLOCK)
 * POST /api/transactions/respond-ato-approval
 */
router.post('/respond-ato-approval', sessionModule.requireAuth, async (req, res) => {
  try {
    const { requestId, approvalDecision } = req.body;
    const userId = req.session.userId;
    const { atoVerificationService } = await import('../services/atoVerificationService.js');

    const result = await atoVerificationService.respondToAtoApproval({
      requestId,
      approvalDecision,
      userId
    });

    return res.status(200).json(result);
  } catch (err) {
    return res.status(400).json({ success: false, message: err.message });
  }
});

/**
 * Status of ATO Verification Request (for Hacker UI / Analyst UI polling)
 * GET /api/transactions/ato-request-status/:requestId
 */
router.get('/ato-request-status/:requestId', async (req, res) => {
  try {
    const { requestId } = req.params;
    const { atoVerificationService } = await import('../services/atoVerificationService.js');
    await atoVerificationService.checkAndExpirePendingRequests();

    const { atoRequestRepository } = await import('../db/atoRequestRepository.js');
    const atoReq = await atoRequestRepository.getAtoRequestById(requestId);

    if (!atoReq) {
      return res.status(404).json({ success: false, message: 'ATO Request not found.' });
    }

    return res.status(200).json({
      success: true,
      atoRequest: atoReq
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

export const bankingModule = {
  name: 'banking',
  router
};
