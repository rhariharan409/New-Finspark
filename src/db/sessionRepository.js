/**
 * Session Repository (Supabase PostgreSQL Integration)
 * Data Access Layer executing queries against the Supabase sessions table.
 */

import { supabase } from './supabaseClient.js';
import { createSessionEntity, SESSION_STATUS } from '../models/sessionModel.js';

export const sessionRepository = {
  /**
   * Persists a new session row in Supabase sessions table
   */
  async createSession(sessionData) {
    const newSession = createSessionEntity(sessionData);

    const { data, error } = await supabase
      .from('sessions')
      .insert([{
        session_id: newSession.session_id,
        user_id: newSession.user_id,
        login_time: newSession.login_time,
        logout_time: newSession.logout_time,
        session_duration_seconds: newSession.session_duration_seconds,
        session_status: newSession.session_status
      }])
      .select()
      .single();

    if (error) {
      console.error('Supabase createSession error:', error.message);
      throw new Error(`Failed to create session record: ${error.message}`);
    }

    return data || newSession;
  },

  /**
   * Finds current active session for a given user ID
   */
  async findActiveSessionByUserId(userId) {
    if (!userId) return null;

    const { data, error } = await supabase
      .from('sessions')
      .select('*')
      .eq('user_id', userId)
      .eq('session_status', SESSION_STATUS.ACTIVE)
      .order('login_time', { ascending: false })
      .limit(1)
      .maybeSingle();

    if (error && error.code !== 'PGRST116') {
      console.error('Supabase findActiveSessionByUserId error:', error.message);
    }

    return data || null;
  },

  /**
   * Finds session row by its unique session ID
   */
  async findSessionById(sessionId) {
    if (!sessionId) return null;

    const { data, error } = await supabase
      .from('sessions')
      .select('*')
      .eq('session_id', sessionId)
      .maybeSingle();

    if (error && error.code !== 'PGRST116') {
      console.error('Supabase findSessionById error:', error.message);
    }

    return data || null;
  },

  async getSessionById(sessionId) {
    return this.findSessionById(sessionId);
  },

  /**
   * Terminates an active session row and updates logout_time and session_duration_seconds
   * (Idempotent: preserves original logout_time and session_duration_seconds if already terminated)
   */
  async terminateSession(sessionId) {
    if (!sessionId) return null;

    // 1. Fetch current session record
    const { data: session, error: fetchErr } = await supabase
      .from('sessions')
      .select('*')
      .eq('session_id', sessionId)
      .maybeSingle();

    if (fetchErr || !session) return null;

    // 2. Only compute duration and UPDATE if currently active
    if (session.session_status === SESSION_STATUS.ACTIVE) {
      const logoutTime = new Date().toISOString();
      const loginMs = new Date(session.login_time).getTime();
      const logoutMs = new Date(logoutTime).getTime();

      let durationSeconds = 0;
      if (!isNaN(loginMs) && !isNaN(logoutMs)) {
        durationSeconds = Math.max(0, Math.floor((logoutMs - loginMs) / 1000));
      }

      const { data: updatedSession, error: updateErr } = await supabase
        .from('sessions')
        .update({
          session_status: SESSION_STATUS.TERMINATED,
          logout_time: logoutTime,
          session_duration_seconds: durationSeconds
        })
        .eq('session_id', sessionId)
        .eq('session_status', SESSION_STATUS.ACTIVE)
        .select()
        .maybeSingle();

      if (updateErr) {
        console.error('Supabase terminateSession error:', updateErr.message);
        throw new Error(`Failed to terminate session: ${updateErr.message}`);
      }

      return updatedSession || {
        ...session,
        session_status: SESSION_STATUS.TERMINATED,
        logout_time: logoutTime,
        session_duration_seconds: durationSeconds
      };
    }

    return session;
  }
};
