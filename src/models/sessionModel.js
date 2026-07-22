/**
 * Session Data Model
 * Defines session fields, duration tracking helpers, and status enumerations for Bank of Turtles.
 */

export const SESSION_STATUS = Object.freeze({
  ACTIVE: 'active',
  TERMINATED: 'terminated'
});

/**
 * Creates a formatted Session entity adhering to system field standards
 */
export function createSessionEntity({
  session_id,
  user_id,
  login_time,
  logout_time,
  session_duration_seconds,
  session_status
}) {
  return {
    session_id: session_id || '',
    user_id: user_id || '',
    login_time: login_time || new Date().toISOString(),
    logout_time: logout_time || null,
    session_duration_seconds: session_duration_seconds !== undefined ? session_duration_seconds : null,
    session_status: session_status || SESSION_STATUS.ACTIVE
  };
}

/**
 * Dynamically calculates current active session duration in seconds (without mutating DB state)
 */
export function calculateActiveSessionDuration(session) {
  if (!session || !session.login_time) return 0;
  const loginMs = new Date(session.login_time).getTime();
  const nowMs = Date.now();
  if (isNaN(loginMs)) return 0;
  return Math.max(0, Math.floor((nowMs - loginMs) / 1000));
}

/**
 * Calculates final session duration in seconds between login_time and logout_time
 */
export function calculateFinalSessionDuration(session) {
  if (!session || !session.login_time || !session.logout_time) return null;
  const loginMs = new Date(session.login_time).getTime();
  const logoutMs = new Date(session.logout_time).getTime();
  if (isNaN(loginMs) || isNaN(logoutMs)) return 0;
  return Math.max(0, Math.floor((logoutMs - loginMs) / 1000));
}
