/**
 * Session Service
 * Business Logic Service handling user session creation, live active duration calculations, session termination, and repository persistence.
 */

import { sessionRepository } from '../db/sessionRepository.js';
import { identityService } from '../security/identityService.js';
import { 
  SESSION_STATUS, 
  calculateActiveSessionDuration, 
  calculateFinalSessionDuration 
} from '../models/sessionModel.js';

export const sessionService = {
  /**
   * Re-export dynamic duration calculation helpers
   */
  calculateActiveSessionDuration,
  calculateFinalSessionDuration,

  /**
   * Creates a new unique application session for an authenticated user
   */
  async createSessionForUser(userId) {
    if (!userId) {
      throw new Error('Session creation error: Valid user_id is required.');
    }

    const sessionId = identityService.generateSessionId();
    const loginTime = new Date().toISOString();

    const sessionEntity = {
      session_id: sessionId,
      user_id: userId,
      login_time: loginTime,
      logout_time: null,
      session_duration_seconds: null,
      session_status: SESSION_STATUS.ACTIVE
    };

    return await sessionRepository.createSession(sessionEntity);
  },

  /**
   * Dynamically calculates or retrieves current session duration in seconds without modifying database state for active sessions.
   * For active sessions: returns current_time - login_time (database remains session_duration_seconds = null).
   * For terminated sessions: returns stored session_duration_seconds.
   */
  async getCurrentSessionDuration(sessionId) {
    if (!sessionId) return null;
    const session = await sessionRepository.findSessionById(sessionId);
    if (!session) return null;

    if (session.session_status === SESSION_STATUS.ACTIVE) {
      return calculateActiveSessionDuration(session);
    }

    if (session.session_duration_seconds !== null && session.session_duration_seconds !== undefined) {
      return session.session_duration_seconds;
    }

    return calculateFinalSessionDuration(session);
  },

  /**
   * Terminates an active session safely and persists final session_duration_seconds
   */
  async terminateSession(sessionId, userId) {
    if (!sessionId) return null;
    try {
      return await sessionRepository.terminateSession(sessionId);
    } catch (error) {
      console.error('Session Termination Error handled safely:', error.message);
      return null;
    }
  },

  /**
   * Retrieves current active session for a given user ID
   */
  async getActiveSession(userId) {
    return await sessionRepository.findActiveSessionByUserId(userId);
  },

  /**
   * Retrieves a session record by its unique session ID
   */
  async getSessionById(sessionId) {
    return await sessionRepository.findSessionById(sessionId);
  }
};
