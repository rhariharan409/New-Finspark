/**
 * User Baseline Repository (Supabase PostgreSQL Integration)
 * Data Access Layer executing query and upsert operations against the Supabase user_baselines table.
 */

import { supabase } from './supabaseClient.js';
import { createBaselineEntity } from '../models/baselineModel.js';

export const baselineRepository = {
  /**
   * Retrieves a user's behavioral baseline by user_id
   */
  async getBaselineByUserId(userId) {
    if (!userId) return null;

    const { data, error } = await supabase
      .from('user_baselines')
      .select('*')
      .eq('user_id', userId)
      .maybeSingle();

    if (error && error.code !== 'PGRST116') {
      console.error('Supabase getBaselineByUserId error:', error.message);
    }

    return data || null;
  },

  /**
   * Upserts a user's behavioral baseline (creates if missing, updates if existing on conflict user_id)
   */
  async upsertBaseline(baselineData) {
    const newBaseline = createBaselineEntity(baselineData);

    const { data, error } = await supabase
      .from('user_baselines')
      .upsert([newBaseline], { onConflict: 'user_id' })
      .select()
      .single();

    if (error) {
      console.error('Supabase upsertBaseline error:', error.message);
      throw new Error(`Failed to upsert user baseline: ${error.message}`);
    }

    return data || newBaseline;
  }
};
