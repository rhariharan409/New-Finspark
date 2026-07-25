import dotenv from 'dotenv';
import { muleService } from '../src/features/mule-intelligence/muleService.js';
import { graphEngine } from '../src/features/mule-intelligence/graphEngine.js';
import { supabase } from '../src/db/supabaseClient.js';

dotenv.config();

async function runFunctionalTests() {
  console.log('====================================================');
  console.log('  MMIE FUNCTIONAL TEST RUN & SCENARIO EVALUATION');
  console.log('====================================================');

  // Re-analyze graph network first so Scenario E and Graph LRs are freshly computed
  console.log('\n--- Running Graph Network Re-analysis ---');
  await graphEngine.rebuildAndAnalyzeNetwork();

  // Test Scenarios
  const scenarios = [
    {
      name: 'Scenario A (Clean Account)',
      senderAccountId: 'ACC-SENDER-GENERIC-1',
      receiverAccountId: 'ACC-TEST-SCENARIO-A-CLEAN',
      expectedOutcome: 'Low mule confidence, allow'
    },
    {
      name: 'Scenario B (Classic Mule Pattern)',
      senderAccountId: 'ACC-SENDER-GENERIC-2',
      receiverAccountId: 'ACC-TEST-SCENARIO-B-MULE',
      expectedOutcome: 'High mule confidence, block or hold'
    },
    {
      name: 'Scenario C (Borderline Account)',
      senderAccountId: 'ACC-SENDER-GENERIC-3',
      receiverAccountId: 'ACC-TEST-SCENARIO-C-BORDERLINE',
      expectedOutcome: 'Mid-range confidence, step_up'
    },
    {
      name: 'Scenario D (Sender-side ATO with Clean Receiver)',
      senderAccountId: 'ACC-TEST-SCENARIO-D-RISKY-SENDER',
      receiverAccountId: 'ACC-TEST-SCENARIO-D-CLEAN-RECEIVER',
      expectedOutcome: 'Low mule confidence on receiver (should NOT be high just because sender is risky)'
    }
  ];

  for (const sc of scenarios) {
    console.log(`\n====================================================`);
    console.log(`Testing: ${sc.name}`);
    console.log(`Expected: ${sc.expectedOutcome}`);
    console.log(`----------------------------------------------------`);

    const result = await muleService.assessTransaction({
      transactionId: `TXN-TEST-${Math.floor(100000 + Math.random() * 900000)}`,
      senderAccountId: sc.senderAccountId,
      receiverAccountId: sc.receiverAccountId
    });

    console.log(`Returned muleConfidence: ${result.muleConfidence}%`);
    console.log(`Returned decision: ${result.decision}`);
    console.log(`Evidence Chain:`, JSON.stringify(result.evidence, null, 2));

    const contribSum = (result.evidence || []).reduce((sum, e) => sum + (e.contributionPct || 0), 0);
    console.log(`Evidence Contribution Sum: ${contribSum}% (Final Score: ${result.muleConfidence}%)`);
  }

  // Check Scenario E Graph Propagation & Rings
  console.log(`\n====================================================`);
  console.log(`Testing: Scenario E (Isolated Ring & Graph Propagation)`);
  console.log(`----------------------------------------------------`);
  
  const scE_nodes = [
    'ACC-TEST-SCENARIO-E-SEED',
    'ACC-TEST-SCENARIO-E-NODE2',
    'ACC-TEST-SCENARIO-E-NODE3',
    'ACC-TEST-SCENARIO-E-UNCONNECTED4',
    'ACC-TEST-SCENARIO-E-UNCONNECTED5'
  ];

  const { data: postures } = await supabase
    .from('mule_posture')
    .select('account_id, graph_reputation, community_id')
    .in('account_id', scE_nodes);

  console.log('Scenario E Postures in DB:', postures);

  const ringData = await graphEngine.getRingsForAccount('ACC-TEST-SCENARIO-E-SEED');
  console.log(`Ring data postures count for Seed: ${ringData.postures?.length}`);
  console.log(`Ring member IDs:`, ringData.postures?.map(p => p.account_id));

  process.exit(0);
}

runFunctionalTests().catch(err => {
  console.error('Error during functional tests:', err);
  process.exit(1);
});
