import dotenv from 'dotenv';
import { supabase } from '../../db/supabaseClient.js';
import { decayHawkesIntensity } from './hawkesEngine.js';
import { graphEngine } from './graphEngine.js';

dotenv.config();

const intervalMs = parseInt(process.env.MULE_POSTURE_INTERVAL_MS) || 90000;
let jobIntervalId = null;

/**
 * Runs a single iteration of the Money Mule Posture background job.
 */
export async function runPostureJobIteration() {
  const startTime = Date.now();
  let updatedCount = 0;

  try {
    // 1. Fetch all accounts with active Hawkes intensities
    const { data: postures, error } = await supabase
      .from('mule_posture')
      .select('*')
      .gt('hawkes_intensity', 0.001);

    if (error) throw error;

    const now = Date.now();

    if (postures && postures.length > 0) {
      for (const p of postures) {
        const lastUpdatedMs = p.hawkes_last_updated ? new Date(p.hawkes_last_updated).getTime() : now;
        
        // Compute decayed intensity
        const decayed = decayHawkesIntensity(
          parseFloat(p.hawkes_intensity) || 0.0,
          lastUpdatedMs,
          now
        );

        // Update decayed Hawkes intensity in database
        await supabase
          .from('mule_posture')
          .update({
            hawkes_intensity: decayed,
            hawkes_last_updated: new Date(now).toISOString()
          })
          .eq('account_id', p.account_id);

        updatedCount++;
      }
    }

    // 2. Re-analyze entity sharing graph network (PageRank + Louvain)
    await graphEngine.rebuildAndAnalyzeNetwork();

    const durationMs = Date.now() - startTime;
    console.log(`[MMIE] posture job updated ${updatedCount} accounts in ${durationMs}ms`);

  } catch (err) {
    console.error('[MMIE] posture job error:', err.message);
  }
}

/**
 * Starts the posture updates setInterval loop.
 */
export function startPostureJob() {
  if (jobIntervalId) {
    console.log('[MMIE] Posture job already running.');
    return;
  }

  console.log(`[MMIE] Starting background posture update job (Interval: ${intervalMs}ms)...`);
  
  // Run once immediately on startup
  runPostureJobIteration();

  jobIntervalId = setInterval(runPostureJobIteration, intervalMs);
}

/**
 * Stops the posture job loop (useful for tests/hot reloads)
 */
export function stopPostureJob() {
  if (jobIntervalId) {
    clearInterval(jobIntervalId);
    jobIntervalId = null;
    console.log('[MMIE] Stopped posture update job.');
  }
}
