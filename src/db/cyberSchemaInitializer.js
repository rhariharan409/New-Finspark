/**
 * Cyber Intelligence Schema Initializer
 * Quantra Correlate
 * Manages cyber analyst authentication, investigation cases, device collision registry, and quantum risk monitoring tables in Supabase PostgreSQL.
 */

import { supabase } from './supabaseClient.js';
import { identityService } from '../security/identityService.js';
import { passwordService } from '../security/passwordService.js';

export const INITIAL_ANALYSTS = [
  {
    analyst_id: 'ANL-001001',
    name: 'Sarah Connor',
    email: 'analyst@quantra.com',
    role: 'Senior Investigator',
    clearance_level: 'Level 3 - Top Secret',
    account_status: 'active'
  },
  {
    analyst_id: 'ANL-001002',
    name: 'Alex Vance',
    email: 'soc@quantra.com',
    role: 'SOC Analyst',
    clearance_level: 'Level 2 - Confidential',
    account_status: 'active'
  },
  {
    analyst_id: 'ANL-001003',
    name: 'Marcus Wright',
    email: 'admin@quantra.com',
    role: 'Administrator',
    clearance_level: 'Level 3 - Top Secret',
    account_status: 'active'
  }
];

export async function initCyberAnalystTables() {
  try {
    // 1. Check if cyber_analysts table is accessible
    const { data: existingAnalysts, error } = await supabase
      .from('cyber_analysts')
      .select('*')
      .limit(10);

    if (error) {
      console.log('Info: cyber_analysts table not present or restricted in Supabase PostgreSQL. Using in-memory fallback store.');
      return;
    }

    if (!existingAnalysts || existingAnalysts.length === 0) {
      console.log('Seeding initial Cyber Analyst accounts into Supabase cyber_analysts table...');
      const defaultPasswordHash = await passwordService.hashPassword('analyst123');
      const adminPasswordHash = await passwordService.hashPassword('admin123');

      const analystsToSeed = INITIAL_ANALYSTS.map(a => ({
        ...a,
        password_hash: a.email.includes('admin') ? adminPasswordHash : defaultPasswordHash,
        created_at: new Date().toISOString()
      }));

      const { error: seedErr } = await supabase
        .from('cyber_analysts')
        .upsert(analystsToSeed, { onConflict: 'email' });

      if (seedErr) {
        console.warn('Could not seed cyber_analysts table:', seedErr.message);
      } else {
        console.log('✅ Initial Cyber Analyst accounts seeded successfully.');
      }
    }
  } catch (err) {
    console.warn('Cyber schema initialization notice:', err.message);
  }
}
