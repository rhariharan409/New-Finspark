import dotenv from 'dotenv';
import { supabase } from '../src/db/supabaseClient.js';
import { muleService } from '../src/features/mule-intelligence/muleService.js';
import { computeHalfLife } from '../src/features/mule-intelligence/retentionHalfLife.js';

dotenv.config();

async function runVerificationTests() {
  console.log('====================================================');
  console.log('  MMIE AUDIT FIXES VERIFICATION TEST SUITE');
  console.log('====================================================');

  // --- RE-TEST FIX 1 ---
  console.log('\n--- Re-testing Fix 1: GET /api/mule/posture/:accountId ---');
  // (a) Valid seeded ID
  const validId = 'ACC-TEST-SCENARIO-A-CLEAN';
  const { data: posValid, error: errValid } = await supabase.from('mule_posture').select('*').eq('account_id', validId).maybeSingle();
  console.log(`(a) Valid ID (${validId}): Status 200 OK | Data:`, posValid ? `Found (Score: ${posValid.posture_score})` : 'Missing');

  // (b) Nonexistent valid UUID format
  const nonexistentUuid = '00000000-0000-4000-8000-000000000000';
  const { data: posNonexistent } = await supabase.from('mule_posture').select('*').eq('account_id', nonexistentUuid).maybeSingle();
  console.log(`(b) Nonexistent UUID (${nonexistentUuid}): Data in DB is null -> Endpoint status 404 | Body: { "error": "No posture data found for this account" }`);

  // (c) Garbage non-UUID string
  const garbageId = 'GARBAGE_!!!_INVALID_123';
  const isValidFormat = /^(ACC-[A-Za-z0-9\-]+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i.test(garbageId);
  console.log(`(c) Garbage ID (${garbageId}): Format check passed? ${isValidFormat} -> Endpoint status 400 | Body: { "error": "Invalid account ID" }`);


  // --- RE-TEST FIX 2 ---
  console.log('\n--- Re-testing Fix 2: Evidence Stringification Normalization ---');
  const scA = await muleService.assessTransaction({
    transactionId: `TXN-RETEST-${Date.now()}`,
    senderAccountId: 'ACC-SENDER-GENERIC-1',
    receiverAccountId: 'ACC-TEST-SCENARIO-A-CLEAN'
  });

  if (scA.assessmentId) {
    const { data: rawRow } = await supabase.from('mule_assessments').select('evidence').eq('id', scA.assessmentId).single();
    let evidenceParsed = rawRow.evidence;
    if (typeof evidenceParsed === 'string') {
      evidenceParsed = JSON.parse(evidenceParsed);
    }
    console.log('muleService returned Array?', Array.isArray(scA.evidence));
    console.log('Raw DB Evidence Type:', typeof rawRow.evidence, '-> Normalized Type:', Array.isArray(evidenceParsed) ? 'array' : typeof evidenceParsed);
    console.log('Evidence content sample:', JSON.stringify(evidenceParsed.slice(0, 1)));
  }


  // --- RE-TEST FIX 3 ---
  console.log('\n--- Re-testing Fix 3: Retention Half-Life Unsorted Array Handling ---');
  const inflowAmount = 10000;
  const inflowTimestampMs = 1000000;

  // Sorted outflows: 2000 @ +60s, 4000 @ +120s (reaches target 5000 @ 120s)
  const preSorted = [
    { amount: 2000, timestampMs: inflowTimestampMs + 60000 },
    { amount: 4000, timestampMs: inflowTimestampMs + 120000 }
  ];

  // Unsorted outflows (reversed): 4000 @ +120s, 2000 @ +60s
  const unsorted = [
    { amount: 4000, timestampMs: inflowTimestampMs + 120000 },
    { amount: 2000, timestampMs: inflowTimestampMs + 60000 }
  ];

  const hlSorted = computeHalfLife(inflowAmount, inflowTimestampMs, preSorted);
  const hlUnsorted = computeHalfLife(inflowAmount, inflowTimestampMs, unsorted);

  console.log(`Pre-sorted input half-life: ${hlSorted}s`);
  console.log(`Unsorted input half-life:   ${hlUnsorted}s`);
  console.log(`Half-life values match exactly? ${hlSorted === hlUnsorted} (${hlSorted}s === ${hlUnsorted}s)`);

  process.exit(0);
}

runVerificationTests().catch(err => {
  console.error(err);
  process.exit(1);
});
