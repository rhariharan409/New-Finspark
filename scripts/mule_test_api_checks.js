import dotenv from 'dotenv';
import { supabase } from '../src/db/supabaseClient.js';
import { muleService } from '../src/features/mule-intelligence/muleService.js';
import { graphEngine } from '../src/features/mule-intelligence/graphEngine.js';
import { runPostureJobIteration } from '../src/features/mule-intelligence/postureJob.js';
import { requireAnalystAuth } from '../src/features/mule-intelligence/muleRoutes.js';

dotenv.config();

async function runApiAndJobChecks() {
  console.log('--- Section 4 & 5 Verification Script ---');

  // 1. GET /api/mule/posture/:accountId with valid vs nonexistent
  const { data: posValid } = await supabase.from('mule_posture').select('*').eq('account_id', 'ACC-TEST-SCENARIO-A-CLEAN').maybeSingle();
  console.log('Valid posture fetch:', posValid ? 'FOUND' : 'NOT FOUND');

  const { data: posInvalid, error: errInvalid } = await supabase.from('mule_posture').select('*').eq('account_id', 'INVALID-NONEXISTENT-UUID-9999').maybeSingle();
  console.log('Nonexistent posture fetch:', posInvalid, 'Err:', errInvalid ? errInvalid.message : 'Clean null/none');

  // 2. Evidence retrieval
  const scA = await muleService.assessTransaction({
    transactionId: 'TXN-EVIDENCE-TEST-001',
    senderAccountId: 'ACC-SENDER-GENERIC-1',
    receiverAccountId: 'ACC-TEST-SCENARIO-A-CLEAN'
  });

  if (scA.assessmentId) {
    const { data: savedEv } = await supabase.from('mule_assessments').select('*').eq('id', scA.assessmentId).single();
    console.log('Stored evidence matches returned evidence exactly?', JSON.stringify(savedEv.evidence) === JSON.stringify(scA.evidence));
  }

  // 3. Background Job Check (postureJob.js)
  // Fetch posture before job run iteration
  const { data: postureBefore } = await supabase.from('mule_posture').select('account_id, last_updated, hawkes_intensity').eq('account_id', 'ACC-TEST-SCENARIO-B-MULE').single();
  
  // Wait 1 second and run iteration
  await new Promise(r => setTimeout(r, 1200));
  await runPostureJobIteration();

  const { data: postureAfter } = await supabase.from('mule_posture').select('account_id, last_updated, hawkes_intensity').eq('account_id', 'ACC-TEST-SCENARIO-B-MULE').single();

  console.log('Posture last_updated changed independently of transactions?', postureBefore.last_updated !== postureAfter.last_updated);
  console.log('Before last_updated:', postureBefore.last_updated, 'After:', postureAfter.last_updated);

  // 4. Require Analyst Auth check
  let mockResStatus = 0;
  let mockResJson = null;
  const mockReq = { session: {} };
  const mockRes = {
    status(code) { mockResStatus = code; return this; },
    json(payload) { mockResJson = payload; return this; }
  };

  // Temporarily clear VERCEL env to test non-Vercel auth behavior
  const origVercel = process.env.VERCEL;
  delete process.env.VERCEL;
  
  requireAnalystAuth(mockReq, mockRes, () => {});
  console.log('Auth check without session returns status:', mockResStatus, 'Payload:', mockResJson);
  process.env.VERCEL = origVercel;

  process.exit(0);
}

runApiAndJobChecks().catch(err => {
  console.error(err);
  process.exit(1);
});
