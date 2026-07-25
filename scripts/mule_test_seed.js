import dotenv from 'dotenv';
import { supabase } from '../src/db/supabaseClient.js';

dotenv.config();

export async function seedTestScenarios() {
  console.log('[SEED] Starting synthetic test data seed script for MMIE verification...');

  // Timestamps
  const now = new Date();
  const nowMs = now.getTime();
  const nowIso = now.toISOString();

  // Helper to generate UUID-like IDs
  const prefixId = (prefix) => `${prefix}-${Math.floor(1000000000 + Math.random() * 9000000000)}`;

  // --------------------------------------------------------------------------
  // SCENARIO A — Clean account (expect low mule confidence, allow)
  // --------------------------------------------------------------------------
  const scA_receiver_acc = 'ACC-TEST-SCENARIO-A-CLEAN';
  const scA_receiver_user = prefixId('USR-SCA');
  
  // Clean posture: no recent velocity, infinite half-life, 0 page rank
  await supabase.from('users').upsert({
    user_id: scA_receiver_user,
    account_id: scA_receiver_acc,
    email: 'test_clean_a@example.com',
    full_name: 'Test Scenario A Clean Receiver'
  }, { onConflict: 'user_id' });

  await supabase.from('mule_posture').upsert({
    account_id: scA_receiver_acc,
    posture_score: 0,
    hawkes_intensity: 0.0,
    hawkes_last_updated: nowIso,
    retention_half_life_seconds: null,
    unique_senders_24h: 0,
    inflow_count_24h: 0,
    community_id: 'comm_clean_a',
    graph_reputation: 0.0,
    last_updated: nowIso
  }, { onConflict: 'account_id' });

  console.log(`SCENARIO_A_RECEIVER_ID=${scA_receiver_acc}`);

  // --------------------------------------------------------------------------
  // SCENARIO B — Classic mule pattern (expect high mule confidence, block/hold)
  // --------------------------------------------------------------------------
  const scB_receiver_acc = 'ACC-TEST-SCENARIO-B-MULE';
  const scB_receiver_user = prefixId('USR-SCB');
  const scB_fraud_seed_acc = 'ACC-TEST-SCENARIO-B-FRAUD-SEED';

  await supabase.from('users').upsert({
    user_id: scB_receiver_user,
    account_id: scB_receiver_acc,
    email: 'test_mule_b@example.com',
    full_name: 'Test Scenario B Mule Receiver'
  }, { onConflict: 'user_id' });

  // Fraud report seed
  await supabase.from('fraud_reports').upsert({
    account_id: scB_fraud_seed_acc,
    reason: 'Synthetic Fraud Seed for Scenario B Test'
  });

  // Shared device edge with fraud seed
  await supabase.from('entity_edges').upsert({
    account_a: scB_receiver_acc,
    account_b: scB_fraud_seed_acc,
    edge_type: 'device',
    token_hash: 'hash_shared_device_scenario_b',
    weight: 2,
    last_seen: nowIso
  }, { onConflict: 'account_a,account_b,edge_type,token_hash' });

  // High Hawkes intensity, short half-life (120s), multiple unique senders
  await supabase.from('mule_posture').upsert({
    account_id: scB_receiver_acc,
    posture_score: 85,
    hawkes_intensity: 3.8,
    hawkes_last_updated: nowIso,
    retention_half_life_seconds: 120,
    unique_senders_24h: 12,
    inflow_count_24h: 18,
    community_id: 'comm_mule_b',
    graph_reputation: 0.005,
    last_updated: nowIso
  }, { onConflict: 'account_id' });

  console.log(`SCENARIO_B_RECEIVER_ID=${scB_receiver_acc}`);
  console.log(`SCENARIO_B_FRAUD_SEED_ID=${scB_fraud_seed_acc}`);

  // --------------------------------------------------------------------------
  // SCENARIO C — Borderline account (expect mid-range confidence, step_up)
  // --------------------------------------------------------------------------
  const scC_receiver_acc = 'ACC-TEST-SCENARIO-C-BORDERLINE';
  const scC_receiver_user = prefixId('USR-SCC');
  const scC_interm_acc = 'ACC-TEST-SCENARIO-C-INTERMEDIARY';
  const scC_fraud_seed_acc = 'ACC-TEST-SCENARIO-C-FRAUD-SEED';

  await supabase.from('users').upsert({
    user_id: scC_receiver_user,
    account_id: scC_receiver_acc,
    email: 'test_borderline_c@example.com',
    full_name: 'Test Scenario C Borderline Receiver'
  }, { onConflict: 'user_id' });

  await supabase.from('fraud_reports').upsert({
    account_id: scC_fraud_seed_acc,
    reason: 'Synthetic Fraud Seed for Scenario C Test'
  });

  // 2-hop connection: Receiver -> Intermediary (IP) -> Fraud Seed (Beneficiary)
  await supabase.from('entity_edges').upsert([
    {
      account_a: scC_receiver_acc,
      account_b: scC_interm_acc,
      edge_type: 'ip',
      token_hash: 'hash_shared_ip_scenario_c',
      weight: 1.5,
      last_seen: nowIso
    },
    {
      account_a: scC_interm_acc,
      account_b: scC_fraud_seed_acc,
      edge_type: 'beneficiary',
      token_hash: 'hash_shared_ben_scenario_c',
      weight: 1.0,
      last_seen: nowIso
    }
  ], { onConflict: 'account_a,account_b,edge_type,token_hash' });

  // Moderate Hawkes (1.5), half-life 7200s (2 hours)
  await supabase.from('mule_posture').upsert({
    account_id: scC_receiver_acc,
    posture_score: 45,
    hawkes_intensity: 1.5,
    hawkes_last_updated: nowIso,
    retention_half_life_seconds: 7200,
    unique_senders_24h: 3,
    inflow_count_24h: 5,
    community_id: 'comm_borderline_c',
    graph_reputation: 0.0008,
    last_updated: nowIso
  }, { onConflict: 'account_id' });

  console.log(`SCENARIO_C_RECEIVER_ID=${scC_receiver_acc}`);

  // --------------------------------------------------------------------------
  // SCENARIO D — Sender-side ATO with clean receiver (expect low/clean receiver mule confidence)
  // --------------------------------------------------------------------------
  const scD_sender_acc = 'ACC-TEST-SCENARIO-D-RISKY-SENDER';
  const scD_sender_user = prefixId('USR-SCD-SENDER');
  const scD_receiver_acc = 'ACC-TEST-SCENARIO-D-CLEAN-RECEIVER';
  const scD_receiver_user = prefixId('USR-SCD-RECEIVER');

  await supabase.from('users').upsert([
    {
      user_id: scD_sender_user,
      account_id: scD_sender_acc,
      email: 'test_sender_d@example.com',
      full_name: 'Test Scenario D Risky Sender'
    },
    {
      user_id: scD_receiver_user,
      account_id: scD_receiver_acc,
      email: 'test_receiver_d@example.com',
      full_name: 'Test Scenario D Clean Receiver'
    }
  ], { onConflict: 'user_id' });

  // Add attack-chain sequence telemetry for sender
  await supabase.from('telemetry_events').insert([
    {
      user_id: scD_sender_user,
      event_type: 'login',
      metadata: { is_new_device: true, description: 'Login from new unrecognized device' },
      event_timestamp: new Date(nowMs - 100000).toISOString()
    },
    {
      user_id: scD_sender_user,
      event_type: 'risk increased',
      metadata: { description: 'critical risk ATO alert' },
      event_timestamp: new Date(nowMs - 80000).toISOString()
    },
    {
      user_id: scD_sender_user,
      event_type: 'new_beneficiary',
      metadata: { description: 'Added new beneficiary recipient' },
      event_timestamp: new Date(nowMs - 50000).toISOString()
    },
    {
      user_id: scD_sender_user,
      event_type: 'transaction_created',
      metadata: { amount: 75000, description: 'Large transfer to recipient' },
      event_timestamp: new Date(nowMs - 20000).toISOString()
    }
  ]);

  // Completely clean receiver posture
  await supabase.from('mule_posture').upsert({
    account_id: scD_receiver_acc,
    posture_score: 0,
    hawkes_intensity: 0.0,
    hawkes_last_updated: nowIso,
    retention_half_life_seconds: null,
    unique_senders_24h: 1,
    inflow_count_24h: 1,
    community_id: 'comm_clean_d',
    graph_reputation: 0.0,
    last_updated: nowIso
  }, { onConflict: 'account_id' });

  console.log(`SCENARIO_D_SENDER_ID=${scD_sender_acc}`);
  console.log(`SCENARIO_D_RECEIVER_ID=${scD_receiver_acc}`);

  // --------------------------------------------------------------------------
  // SCENARIO E — Isolated ring (expect Louvain cluster for connected nodes, PageRank elevated near seed)
  // --------------------------------------------------------------------------
  const scE_seed_acc = 'ACC-TEST-SCENARIO-E-SEED';
  const scE_node2_acc = 'ACC-TEST-SCENARIO-E-NODE2';
  const scE_node3_acc = 'ACC-TEST-SCENARIO-E-NODE3';
  const scE_unconnected4_acc = 'ACC-TEST-SCENARIO-E-UNCONNECTED4';
  const scE_unconnected5_acc = 'ACC-TEST-SCENARIO-E-UNCONNECTED5';

  await supabase.from('fraud_reports').upsert({
    account_id: scE_seed_acc,
    reason: 'Synthetic Fraud Seed for Scenario E Test'
  });

  // Edge: Seed <-> Node2 (device)
  await supabase.from('entity_edges').upsert({
    account_a: scE_seed_acc,
    account_b: scE_node2_acc,
    edge_type: 'device',
    token_hash: 'hash_device_scenario_e',
    weight: 2,
    last_seen: nowIso
  }, { onConflict: 'account_a,account_b,edge_type,token_hash' });

  // Edge: Node2 <-> Node3 (ip)
  await supabase.from('entity_edges').upsert({
    account_a: scE_node2_acc,
    account_b: scE_node3_acc,
    edge_type: 'ip',
    token_hash: 'hash_ip_scenario_e',
    weight: 1.5,
    last_seen: nowIso
  }, { onConflict: 'account_a,account_b,edge_type,token_hash' });

  // Initial postures for Scenario E nodes
  for (const accId of [scE_seed_acc, scE_node2_acc, scE_node3_acc, scE_unconnected4_acc, scE_unconnected5_acc]) {
    await supabase.from('mule_posture').upsert({
      account_id: accId,
      posture_score: accId === scE_seed_acc ? 95 : 0,
      hawkes_intensity: 0.0,
      hawkes_last_updated: nowIso,
      retention_half_life_seconds: null,
      unique_senders_24h: 0,
      inflow_count_24h: 0,
      community_id: 'default',
      graph_reputation: 0.0,
      last_updated: nowIso
    }, { onConflict: 'account_id' });
  }

  console.log(`SCENARIO_E_SEED_ID=${scE_seed_acc}`);
  console.log(`SCENARIO_E_NODE2_ID=${scE_node2_acc}`);
  console.log(`SCENARIO_E_NODE3_ID=${scE_node3_acc}`);
  console.log(`SCENARIO_E_UNCONNECTED4_ID=${scE_unconnected4_acc}`);
  console.log(`SCENARIO_E_UNCONNECTED5_ID=${scE_unconnected5_acc}`);

  console.log('[SEED] Synthetic test data seed script completed successfully.');
}

// Run directly if invoked via CLI
if (process.argv[1].endsWith('mule_test_seed.js')) {
  seedTestScenarios().then(() => process.exit(0)).catch(err => {
    console.error('[SEED] Error:', err);
    process.exit(1);
  });
}
