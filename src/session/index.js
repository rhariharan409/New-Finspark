/**
 * Session Management Area
 * Handles user authentication sessions, session integrity verification, and protection middleware.
 */

import { sessionIntegrityEngine } from '../services/sessionIntegrityEngine.js';
import { sessionService } from '../services/sessionService.js';

export const sessionModule = {
  name: 'session',

  /**
   * Middleware to enforce authenticated session and real-time session integrity validation on protected routes
   */
  async requireAuth(req, res, next) {
    if (req.session && req.session.userId) {
      try {
        const validation = await sessionIntegrityEngine.validateRequestSession(req);
        req.sessionIntegrity = validation;

        // Automated Enforcement: Block & Invalidate Session if Risk Score >= 90
        if (validation && validation.action === 'BLOCK') {
          const sessionId = req.session.sessionId;
          const userId = req.session.userId;
          if (sessionId) {
            await sessionService.terminateSession(sessionId, userId);
          }
          req.session.destroy(() => {});
          return res.status(403).json({
            success: false,
            code: 'ATO_SESSION_TERMINATED',
            message: 'Security Action: Account Takeover (ATO) risk threshold exceeded (Score >= 90). Session invalidated immediately.',
            evidence: validation.evidence
          });
        }
      } catch (err) {
        console.error('Session Integrity Middleware Error:', err.message);
      }
      return next();
    }
    return res.status(401).json({
      success: false,
      message: 'Unauthorized. Active session required.'
    });
  },

  /**
   * Helper to format safe session payload
   */
  setSessionUser(req, user) {
    const userId = user.user_id || user.id;
    const accountId = user.account_id || user.accountNumber;
    const fullName = user.full_name || user.fullName;

    req.session.userId = userId;
    req.session.username = user.username || user.email;
    req.session.user = {
      user_id: userId,
      account_id: accountId,
      full_name: fullName,
      email: user.email,
      account_status: user.account_status || 'active'
    };
  },

  /**
   * Clear active user session
   */
  destroySession(req) {
    return new Promise((resolve, reject) => {
      if (!req.session) return resolve(true);
      req.session.destroy((err) => {
        if (err) return reject(err);
        resolve(true);
      });
    });
  }
};
