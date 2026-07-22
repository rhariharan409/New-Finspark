/**
 * Identity Generation Service
 * Generates cryptographically secure, non-predictable user, bank account, session, transaction, telemetry event, baseline, and risk decision identifiers for Bank of Turtles.
 */

import crypto from 'crypto';

export const identityService = {
  /**
   * Generates a unique internal identifier for a user.
   * Format: USR-XXXXXXXX (8 uppercase alphanumeric characters)
   */
  generateUserId() {
    const randomHex = crypto.randomBytes(4).toString('hex').toUpperCase();
    return `USR-${randomHex}`;
  },

  /**
   * Generates a unique bank account identifier safe for public display.
   * Format: ACC-XXXXXXXXXXXX (12 uppercase alphanumeric characters)
   */
  generateAccountId() {
    const randomHex = crypto.randomBytes(6).toString('hex').toUpperCase();
    return `ACC-${randomHex}`;
  },

  /**
   * Generates a unique session identifier for an authenticated session.
   * Format: SES-XXXXXXXX (8 uppercase alphanumeric characters)
   */
  generateSessionId() {
    const randomHex = crypto.randomBytes(4).toString('hex').toUpperCase();
    return `SES-${randomHex}`;
  },

  /**
   * Generates a unique transaction identifier for a monetary transfer.
   * Format: TXN-XXXXXXXX (8 uppercase alphanumeric characters)
   */
  generateTransactionId() {
    const randomHex = crypto.randomBytes(4).toString('hex').toUpperCase();
    return `TXN-${randomHex}`;
  },

  /**
   * Generates a unique telemetry event identifier.
   * Format: EVT-XXXXXXXX (8 uppercase alphanumeric characters)
   */
  generateEventId() {
    const randomHex = crypto.randomBytes(4).toString('hex').toUpperCase();
    return `EVT-${randomHex}`;
  },

  /**
   * Generates a unique behavioral baseline identifier.
   * Format: BSL-XXXXXXXX (8 uppercase alphanumeric characters)
   */
  generateBaselineId() {
    const randomHex = crypto.randomBytes(4).toString('hex').toUpperCase();
    return `BSL-${randomHex}`;
  },

  /**
   * Generates a unique risk decision identifier.
   * Format: RSK-XXXXXXXX (8 uppercase alphanumeric characters)
   */
  generateRiskDecisionId() {
    const randomHex = crypto.randomBytes(4).toString('hex').toUpperCase();
    return `RSK-${randomHex}`;
  }
};
