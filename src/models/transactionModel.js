/**
 * Transaction Data Model
 * Defines transaction fields, defaults, and formatting for Bank of Turtles.
 */

export const TRANSACTION_STATUS = Object.freeze({
  COMPLETED: 'completed',
  FAILED: 'failed',
  PENDING: 'pending'
});

export const TRANSACTION_TYPE = Object.freeze({
  TRANSFER: 'transfer',
  PAYMENT: 'payment',
  DEPOSIT: 'deposit'
});

/**
 * Creates a formatted Transaction entity adhering to system standards
 */
export function createTransactionEntity({
  transaction_id,
  session_id,
  sender_user_id,
  receiver_user_id,
  amount,
  currency,
  transaction_type,
  transaction_status,
  transaction_timestamp,
  description,
  created_at
}) {
  return {
    transaction_id: transaction_id || '',
    session_id: session_id || null,
    sender_user_id: sender_user_id || '',
    receiver_user_id: receiver_user_id || '',
    amount: parseFloat(amount) || 0,
    currency: currency || 'INR',
    transaction_type: transaction_type || TRANSACTION_TYPE.TRANSFER,
    transaction_status: transaction_status || TRANSACTION_STATUS.COMPLETED,
    transaction_timestamp: transaction_timestamp || new Date().toISOString(),
    description: description || '',
    created_at: created_at || new Date().toISOString()
  };
}
