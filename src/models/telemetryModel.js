/**
 * Telemetry Event Data Model
 * Defines telemetry fields, allowed event types, and entity formatting for Bank of Turtles.
 */

export const TELEMETRY_EVENT_TYPE = Object.freeze({
  LOGIN: 'login',
  LOGOUT: 'logout',
  TRANSACTION_CREATED: 'transaction_created',
  TRANSACTION_COMPLETED: 'transaction_completed',
  TRANSACTION_FAILED: 'transaction_failed',
  PASSWORD_CHANGE: 'password_change',
  DEVICE_CHANGE: 'device_change',
  LOCATION_CHANGE: 'location_change',
  SESSION_STARTED: 'session_started',
  SESSION_TERMINATED: 'session_terminated'
});

const ALLOWED_TYPES_SET = new Set(Object.values(TELEMETRY_EVENT_TYPE));

/**
 * Validates if an event_type string is supported
 */
export function isValidEventType(type) {
  return typeof type === 'string' && ALLOWED_TYPES_SET.has(type.toLowerCase().trim());
}

/**
 * Creates a formatted Telemetry Event entity adhering to system standards
 */
export function createTelemetryEntity({
  event_id,
  user_id,
  session_id,
  transaction_id,
  event_type,
  event_timestamp,
  ip_address,
  device_id,
  device_type,
  location,
  metadata,
  created_at
}) {
  return {
    event_id: event_id || '',
    user_id: user_id || '',
    session_id: session_id || null,
    transaction_id: transaction_id || null,
    event_type: (event_type || '').toLowerCase().trim(),
    event_timestamp: event_timestamp || new Date().toISOString(),
    ip_address: ip_address || null,
    device_id: device_id || null,
    device_type: device_type || null,
    location: location || null,
    metadata: metadata && typeof metadata === 'object' ? metadata : {},
    created_at: created_at || new Date().toISOString()
  };
}
