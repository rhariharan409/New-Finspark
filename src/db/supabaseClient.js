/**
 * Central Supabase Client Module
 * Bank of Turtles
 * Connects to Supabase PostgreSQL Database using environment variables.
 */

import { createClient } from '@supabase/supabase-js';
import dotenv from 'dotenv';

dotenv.config();

const supabaseUrl = process.env.SUPABASE_URL || 'https://eccwmmwbmyboeahlaexo.supabase.co';
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY || '';

if (!supabaseAnonKey || supabaseAnonKey === 'YOUR_SUPABASE_ANON_KEY_HERE') {
  console.warn('⚠️ WARNING: SUPABASE_ANON_KEY is not set or using placeholder in .env. Please update .env with your valid key.');
}

export const supabase = createClient(supabaseUrl, supabaseAnonKey, {
  auth: {
    persistSession: false
  }
});
