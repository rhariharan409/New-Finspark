/**
 * Telemetry Repository (Supabase PostgreSQL Integration)
 * Data Access Layer executing queries against the Supabase telemetry_events table.
 */

import { supabase } from './supabaseClient.js';
import { createTelemetryEntity } from '../models/telemetryModel.js';

export const telemetryRepository = {
  /**
   * Persists a new Telemetry Event row in Supabase telemetry_events table
   */
  async recordEvent(eventData) {
    const newEvent = createTelemetryEntity(eventData);

    const { data, error } = await supabase
      .from('telemetry_events')
      .insert([{
        event_id: newEvent.event_id,
        user_id: newEvent.user_id,
        session_id: newEvent.session_id,
        transaction_id: newEvent.transaction_id,
        event_type: newEvent.event_type,
        event_timestamp: newEvent.event_timestamp,
        ip_address: newEvent.ip_address,
        device_id: newEvent.device_id,
        device_type: newEvent.device_type,
        location: newEvent.location,
        metadata: newEvent.metadata,
        created_at: newEvent.created_at
      }])
      .select()
      .single();

    if (error) {
      console.error('Supabase recordEvent error:', error.message);
      throw new Error(`Failed to record telemetry event: ${error.message}`);
    }

    return data || newEvent;
  },

  /**
   * Retrieves telemetry events for a given user ID (newest first), with optional event_type filtering
   */
  async getEventsForUser(userId, { eventType } = {}) {
    if (!userId) return [];

    let query = supabase
      .from('telemetry_events')
      .select('*')
      .eq('user_id', userId);

    if (eventType) {
      query = query.eq('event_type', eventType.toLowerCase().trim());
    }

    const { data, error } = await query.order('event_timestamp', { ascending: false });

    if (error) {
      console.error('Supabase getEventsForUser error:', error.message);
      throw new Error(`Failed to retrieve telemetry events: ${error.message}`);
    }

    return data || [];
  }
};
