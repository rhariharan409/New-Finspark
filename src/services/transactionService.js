/**
 * Transaction Service
 * Business Logic Service for handling monetary transaction validations and operations.
 */

import { transactionRepository } from '../db/transactionRepository.js';
import { userRepository } from '../db/userRepository.js';
import { telemetryRepository } from '../db/telemetryRepository.js';
import { sessionService } from './sessionService.js';
import { identityService } from '../security/identityService.js';

export const transactionService = {
  /**
   * Executes a new transaction between a sender and a receiver, automatically linked to the active session
   */
  async createTransaction({ senderUserId, sessionId, receiverIdentifier, amount, transactionType, description }) {
    // 1. Validate Sender Authentication
    if (!senderUserId) {
      throw new Error('Sender user ID is required for transactions.');
    }

    // 2. Validate Amount > 0
    const parsedAmount = parseFloat(amount);
    if (isNaN(parsedAmount) || parsedAmount <= 0) {
      throw new Error('Transaction amount must be greater than zero.');
    }

    // 3. Validate Receiver Identifier
    if (!receiverIdentifier || typeof receiverIdentifier !== 'string' || receiverIdentifier.trim().length === 0) {
      throw new Error('Receiver identifier (User ID, Email, or Account ID) is required.');
    }

    const cleanReceiverId = receiverIdentifier.trim();

    // 4. Resolve Receiver User in Database
    const receiverUser = (await userRepository.findUserById(cleanReceiverId)) ||
                         (await userRepository.findUserByEmail(cleanReceiverId)) ||
                         (await userRepository.findUserByAccountId(cleanReceiverId));

    if (!receiverUser) {
      throw new Error(`Receiver '${cleanReceiverId}' was not found in the database.`);
    }

    // 5. Prevent Self-Transactions
    if (senderUserId === receiverUser.user_id) {
      throw new Error('Self-transactions are not permitted. Sender and receiver cannot be the same user.');
    }

    // 6. Derive Active Session from Authenticated User if not provided
    let activeSessionId = sessionId || null;
    if (!activeSessionId) {
      const activeSession = await sessionService.getActiveSession(senderUserId);
      if (activeSession) {
        activeSessionId = activeSession.session_id;
      }
    }

    // 7. Generate Transaction ID & Entity
    const transactionId = identityService.generateTransactionId();

    const transactionData = {
      transaction_id: transactionId,
      session_id: activeSessionId,
      sender_user_id: senderUserId,
      receiver_user_id: receiverUser.user_id,
      amount: parsedAmount,
      currency: 'INR',
      transaction_type: transactionType || 'transfer',
      transaction_status: 'completed',
      transaction_timestamp: new Date().toISOString(),
      description: description || ''
    };

    // 8. Persist to Supabase transactions table
    return await transactionRepository.createTransaction(transactionData);
  },

  /**
   * Calculates dynamic session-level transaction summary metrics from the transactions table
   */
  async getSessionTransactionSummary(sessionId, userId = null) {
    if (!sessionId) {
      return {
        session_id: null,
        transaction_count: 0,
        total_amount_transacted: 0,
        average_transaction_amount: 0,
        successful_transactions_count: 0,
        failed_transactions_count: 0,
        unique_receiver_count: 0,
        first_transaction_timestamp: null,
        last_transaction_timestamp: null
      };
    }

    // Retrieve transactions for this session_id
    const sessionTxns = await transactionRepository.getTransactionsForSession(sessionId);
    const sentTxns = userId ? sessionTxns.filter(t => t.sender_user_id === userId) : sessionTxns;

    // Retrieve failed events for this session_id from telemetry
    let failedCount = 0;
    if (userId) {
      const userTelemetry = await telemetryRepository.getEventsForUser(userId);
      failedCount = userTelemetry.filter(e => e.session_id === sessionId && e.event_type === 'transaction_failed').length;
    }

    const transactionCount = sentTxns.length;
    const totalAmount = sentTxns.reduce((sum, t) => sum + (parseFloat(t.amount) || 0), 0);
    const roundedTotal = Math.round(totalAmount * 100) / 100;
    const avgAmount = transactionCount > 0 ? Math.round((totalAmount / transactionCount) * 100) / 100 : 0;
    const successfulCount = sentTxns.filter(t => t.transaction_status === 'completed' || !t.transaction_status).length;
    const uniqueReceivers = new Set(sentTxns.map(t => t.receiver_user_id).filter(Boolean));

    const timestamps = sentTxns
      .map(t => t.transaction_timestamp || t.created_at)
      .filter(Boolean)
      .sort((a, b) => new Date(a).getTime() - new Date(b).getTime());

    const firstTimestamp = timestamps.length > 0 ? timestamps[0] : null;
    const lastTimestamp = timestamps.length > 0 ? timestamps[timestamps.length - 1] : null;

    return {
      session_id: sessionId,
      transaction_count: transactionCount,
      total_amount_transacted: roundedTotal,
      average_transaction_amount: avgAmount,
      successful_transactions_count: successfulCount,
      failed_transactions_count: failedCount,
      unique_receiver_count: uniqueReceivers.size,
      first_transaction_timestamp: firstTimestamp,
      last_transaction_timestamp: lastTimestamp
    };
  },

  /**
   * Retrieves transaction history for an authenticated user (where user is sender or receiver)
   */
  async getUserTransactions(userId) {
    if (!userId) {
      throw new Error('User ID is required to retrieve transaction history.');
    }
    return await transactionRepository.getTransactionsForUser(userId);
  }
};

/**
 * Reusable backend function for retrieving session-level transaction summary
 */
export async function getSessionTransactionSummary(sessionId, userId = null) {
  return await transactionService.getSessionTransactionSummary(sessionId, userId);
}
