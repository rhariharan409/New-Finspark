/**
 * Behavioral Telemetry API Router
 * Implements REST endpoints for querying and recording behavioral telemetry events.
 */

import express from 'express';
import { telemetryService } from '../services/telemetryService.js';
import { sessionModule } from '../session/index.js';
import { isValidEventType } from '../models/telemetryModel.js';

const router = express.Router();

/**
 * Get Authenticated User Telemetry Events API
 * GET /api/telemetry
 */
router.get('/', sessionModule.requireAuth, async (req, res) => {
  try {
    // Derive user ID strictly from authenticated session cookie
    const userId = req.session.userId;
    const { event_type } = req.query;

    const events = await telemetryService.getUserTelemetryEvents(userId, {
      eventType: event_type || null
    });

    return res.status(200).json({
      success: true,
      count: events.length,
      events
    });

  } catch (error) {
    console.error('Telemetry GET Error:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Failed to retrieve telemetry events history.'
    });
  }
});

/**
 * Internal Testing Endpoint: Post Custom Telemetry Event
 * POST /api/telemetry
 */
router.post('/', sessionModule.requireAuth, async (req, res) => {
  try {
    // Derive user ID strictly from authenticated session cookie
    const userId = req.session.userId;
    const sessionId = req.session.sessionId || null;
    const { event_type, transaction_id, metadata, location, device_id } = req.body;

    if (!event_type || !isValidEventType(event_type)) {
      return res.status(400).json({
        success: false,
        message: `Invalid or unsupported event_type '${event_type}'.`
      });
    }

    const clientDetails = telemetryService.extractClientDetails(req);

    const event = await telemetryService.recordTelemetryEvent({
      userId,
      sessionId,
      transactionId: transaction_id || null,
      eventType: event_type,
      ipAddress: clientDetails.ipAddress,
      deviceType: clientDetails.deviceType,
      deviceId: device_id || null,
      location: location || null,
      metadata: metadata || {}
    });

    return res.status(201).json({
      success: true,
      message: 'Telemetry event recorded successfully.',
      event
    });

  } catch (error) {
    console.error('Telemetry POST Error:', error.message);
    return res.status(400).json({
      success: false,
      message: error.message || 'Failed to record telemetry event.'
    });
  }
});

export const telemetryModule = {
  name: 'telemetry',
  router
};
