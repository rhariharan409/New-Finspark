/**
 * Behavioral Telemetry Service
 * Business Logic Service for validating and capturing behavioral events across authentication, session, and transaction lifecycles.
 */

import { telemetryRepository } from '../db/telemetryRepository.js';
import { identityService } from '../security/identityService.js';
import { isValidEventType } from '../models/telemetryModel.js';

export const telemetryService = {
  /**
   * Validates and records a telemetry event in Supabase
   */
  async recordTelemetryEvent({
    userId,
    sessionId = null,
    transactionId = null,
    eventType,
    ipAddress = null,
    deviceId = null,
    deviceType = null,
    location = null,
    metadata = {}
  }) {
    // 1. Validate User ID
    if (!userId) {
      throw new Error('Telemetry event recording error: User ID is required.');
    }

    // 2. Validate Event Type
    if (!eventType || !isValidEventType(eventType)) {
      throw new Error(`Telemetry event recording error: Invalid event_type '${eventType}'.`);
    }

    // 3. Generate Event ID
    const eventId = identityService.generateEventId();

    const eventPayload = {
      event_id: eventId,
      user_id: userId,
      session_id: sessionId || null,
      transaction_id: transactionId || null,
      event_type: eventType.toLowerCase().trim(),
      event_timestamp: new Date().toISOString(),
      ip_address: ipAddress || null,
      device_id: deviceId || null,
      device_type: deviceType || null,
      location: location || null,
      metadata: metadata && typeof metadata === 'object' ? metadata : {}
    };

    // 4. Persist to Supabase telemetry_events table
    return await telemetryRepository.recordEvent(eventPayload);
  },

  /**
   * Retrieves telemetry events history for a user (newest first), with optional filtering by event_type
   */
  async getUserTelemetryEvents(userId, options = {}) {
    if (!userId) {
      throw new Error('User ID is required to retrieve telemetry events.');
    }
    return await telemetryRepository.getEventsForUser(userId, options);
  },

  /**
   * Utility helper to extract client IP address and user-agent details from Express HTTP request
   */
  extractClientDetails(req) {
    if (!req) return { ipAddress: null, deviceType: null };
    const ipAddress = req.headers['x-forwarded-for'] || req.socket?.remoteAddress || req.ip || null;
    const userAgent = req.headers['user-agent'] || null;
    return {
      ipAddress: typeof ipAddress === 'string' ? ipAddress.split(',')[0].trim() : ipAddress,
      deviceType: userAgent ? (userAgent.length > 100 ? userAgent.substring(0, 100) : userAgent) : 'browser'
    };
  }
};
