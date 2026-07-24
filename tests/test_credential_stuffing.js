/**
 * Native Node.js Test Suite for Credential Stuffing & Behavioral Auth Engine
 * Tests 7 core unit cases, 3 attack simulator scenarios, and Welford algorithm statistics.
 */

import assert from 'node:assert/strict';
import { CredentialStuffingDetector, evaluateLoginEvent } from '../src/security/credential_stuffing/credentialStuffingDetector.js';
import { DetectorRegistry } from '../src/security/credential_stuffing/detectorRegistry.js';
import { IPWindowStore } from '../src/security/credential_stuffing/ipWindowStore.js';
import { UserWindowStore } from '../src/security/credential_stuffing/userWindowStore.js';
import { PasswordHashWindowStore } from '../src/security/credential_stuffing/passwordHashWindowStore.js';
import { BaselineTracker } from '../src/security/credential_stuffing/baselineTracker.js';
import { SCENARIO_DEFINITIONS } from '../src/security/credential_stuffing/scenarioDefinitions.js';

const LEGIT_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

console.log('================================================================');
console.log('  RUNNING NATIVE NODE.JS CREDENTIAL STUFFING DETECTOR TEST SUITE');
console.log('================================================================\n');

let passedTests = 0;

function runTest(testName, fn) {
  try {
    fn();
    console.log(`[PASS] ${testName}`);
    passedTests++;
  } catch (err) {
    console.error(`[FAIL] ${testName}`);
    console.error(err);
    process.exit(1);
  }
}

// -----------------------------------------------------------------------------
// 1. UNIT TESTS (7 TEST CASES)
// -----------------------------------------------------------------------------

runTest('TEST 1: Normal login — no alert', () => {
  const detector = new CredentialStuffingDetector();
  const event = {
    event_id: 'evt_norm_1',
    event_type: 'login',
    entity_id: 'USER_NORMAL',
    ip_address: '192.168.1.1',
    timestamp: new Date(),
    payload: { login_success: true, user_agent: LEGIT_UA }
  };

  const res = detector.detect(event);
  assert.equal(res.score, 0.0);
  assert.equal(res.reasons.length, 0);
});

runTest('TEST 2: Brute force detection', () => {
  const detector = new CredentialStuffingDetector();
  const now = new Date();
  const results = [];

  for (let i = 0; i < 6; i++) {
    const event = {
      event_id: `evt_bf_${i}`,
      event_type: 'login',
      entity_id: 'USER_VICTIM',
      ip_address: '10.0.0.1',
      timestamp: new Date(now.getTime() + i * 1000),
      payload: {
        login_success: false,
        password_hash: `pass_guess_${String(i).padStart(4, '0')}`,
        user_agent: LEGIT_UA
      }
    };
    results.push(detector.detect(event));
  }

  const finalRes = results[results.length - 1];
  assert.ok(finalRes.score >= 45.0, `Expected score >= 45, got ${finalRes.score}`);
  const reasonsText = finalRes.reasons.join(' ').toLowerCase();
  assert.ok(reasonsText.includes('brute force'), 'Expected reason to contain brute force');
});

runTest('TEST 3: Credential spray detection', () => {
  const detector = new CredentialStuffingDetector();
  const now = new Date();
  const results = [];

  for (let i = 0; i < 8; i++) {
    const event = {
      event_id: `evt_spray_${i}`,
      event_type: 'login',
      entity_id: `USER_${i + 1}`,
      ip_address: '198.51.100.42',
      timestamp: new Date(now.getTime() + i * 1000),
      payload: {
        login_success: false,
        password_hash: `stolen_hash_${String(i).padStart(4, '0')}`,
        user_agent: LEGIT_UA
      }
    };
    results.push(detector.detect(event));
  }

  const finalRes = results[results.length - 1];
  assert.ok(finalRes.score >= 40.0, `Expected score >= 40, got ${finalRes.score}`);
  const reasonsText = finalRes.reasons.join(' ').toLowerCase();
  assert.ok(reasonsText.includes('credential spray'), 'Expected reason to contain credential spray');
});

runTest('TEST 4: NAT suppression — shared IP, low failure rate', () => {
  const detector = new CredentialStuffingDetector();
  const now = new Date();

  // 4 success events from 172.16.0.1, spaced 70s apart to stay below velocity threshold
  for (let i = 0; i < 4; i++) {
    detector.detect({
      event_id: `evt_nat_succ_${i}`,
      event_type: 'login',
      entity_id: `USER_NAT_${i}`,
      ip_address: '172.16.0.1',
      timestamp: new Date(now.getTime() + i * 70000),
      payload: { login_success: true, user_agent: LEGIT_UA }
    });
  }

  // 5th event from same IP, different user, login_success = false, 70s later
  const res5th = detector.detect({
    event_id: 'evt_nat_fail_5',
    event_type: 'login',
    entity_id: 'USER_NAT_4',
    ip_address: '172.16.0.1',
    timestamp: new Date(now.getTime() + 4 * 70000),
    payload: { login_success: false, user_agent: LEGIT_UA }
  });

  assert.ok(res5th.score < 40.0, `Expected score < 40 for NAT suppression, got ${res5th.score}`);
  assert.equal(res5th.evidence_metadata.rule, 'credential_spray_suppressed_nat');
});

runTest('TEST 5: Password spray detection', () => {
  const detector = new CredentialStuffingDetector();
  const now = new Date();
  const results = [];

  for (let i = 0; i < 5; i++) {
    const event = {
      event_id: `evt_pwspray_${i}`,
      event_type: 'login',
      entity_id: `USER_PW_${i}`,
      ip_address: `203.0.113.${10 + i}`,
      timestamp: new Date(now.getTime() + i * 1000),
      payload: {
        login_success: false,
        password_hash: 'test_spray_hash',
        user_agent: LEGIT_UA
      }
    };
    results.push(detector.detect(event));
  }

  const finalRes = results[results.length - 1];
  assert.ok(finalRes.score >= 35.0, `Expected score >= 35, got ${finalRes.score}`);
  const reasonsText = finalRes.reasons.join(' ').toLowerCase();
  assert.ok(reasonsText.includes('password spray') || reasonsText.includes('spraying'), 'Expected reason to contain password spray');
});

runTest('TEST 6: Bot signature — low score alone', () => {
  const detector = new CredentialStuffingDetector();
  const res = detector.detect({
    event_id: 'evt_bot_1',
    event_type: 'login',
    entity_id: 'USER_BOT',
    ip_address: '192.168.1.50',
    timestamp: new Date(),
    payload: {
      login_success: false,
      user_agent: 'python-requests/2.28.0'
    }
  });

  assert.equal(res.score, 15.0);
  assert.ok(res.score < 40.0);
});

runTest('TEST 7: Non-login event — ignored', () => {
  const detector = new CredentialStuffingDetector();
  const res = detector.detect({
    event_id: 'evt_tx_1',
    event_type: 'transaction',
    entity_id: 'USER_TX',
    ip_address: '192.168.1.1',
    timestamp: new Date(),
    payload: { amount: 1000 }
  });

  assert.equal(res.score, 0.0);
  assert.equal(res.reasons.length, 0);
});

// -----------------------------------------------------------------------------
// 2. SCENARIO SIMULATION TESTS (3 SCENARIOS)
// -----------------------------------------------------------------------------

runTest('SCENARIO 1: CREDENTIAL_STUFFING_SPRAY scenario', () => {
  const scenario = SCENARIO_DEFINITIONS.CREDENTIAL_STUFFING_SPRAY;
  const detector = new CredentialStuffingDetector();
  const results = scenario.events.map(ev => detector.detect(ev));
  const finalRes = results[results.length - 1];

  assert.ok(finalRes.score >= 65.0, `Expected score >= 65.0, got ${finalRes.score}`);
  const reasonsText = finalRes.reasons.join(' ');
  assert.ok(reasonsText.includes('Credential spray'));
  assert.ok(reasonsText.includes('Automated failure pattern'));
});

runTest('SCENARIO 2: BRUTE_FORCE_SINGLE_ACCOUNT scenario', () => {
  const scenario = SCENARIO_DEFINITIONS.BRUTE_FORCE_SINGLE_ACCOUNT;
  const detector = new CredentialStuffingDetector();
  const results = scenario.events.map(ev => detector.detect(ev));
  const finalRes = results[results.length - 1];

  assert.ok(finalRes.score >= 70.0, `Expected score >= 70.0, got ${finalRes.score}`);
  const reasonsText = finalRes.reasons.join(' ');
  assert.ok(reasonsText.includes('Account brute force'));
  assert.ok(reasonsText.includes('Automated failure pattern'));
});

runTest('SCENARIO 3: PASSWORD_SPRAY_DISTRIBUTED scenario', () => {
  const scenario = SCENARIO_DEFINITIONS.PASSWORD_SPRAY_DISTRIBUTED;
  const detector = new CredentialStuffingDetector();
  const results = scenario.events.map(ev => detector.detect(ev));

  const res5th = results[4];
  const res6th = results[5];

  assert.ok(res5th.score >= 35.0);
  assert.ok(res5th.reasons.some(r => r.includes('Password spraying')));
  assert.ok(res6th.score >= 35.0);
  assert.ok(res6th.reasons.some(r => r.includes('Password spraying')));
});

// -----------------------------------------------------------------------------
// 3. STATISTICAL BASELINE & REGISTRY TESTS
// -----------------------------------------------------------------------------

runTest('BaselineTracker Welford Algorithm calculations', () => {
  const tracker = new BaselineTracker(10);
  const entityId = 'user_welford_node';

  const values = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0];
  values.forEach(v => tracker.update(entityId, v));

  const stats = tracker.getStats(entityId);
  assert.equal(stats.count, 10);
  assert.ok(Math.abs(stats.mean - 5.5) < 1e-5, `Expected mean 5.5, got ${stats.mean}`);

  const res = tracker.getThreshold(entityId, 2.5, 5.0);
  const expectedThresh = 5.5 + (2.5 * stats.stdDev);
  assert.ok(Math.abs(res.threshold - expectedThresh) < 1e-3);
});

runTest('DetectorRegistry Auto-Discovery', () => {
  const registered = DetectorRegistry.get('credential_stuffing_detector');
  assert.ok(registered, 'CredentialStuffingDetector should be registered in DetectorRegistry');
  assert.equal(registered.detectorName, 'credential_stuffing_detector');
});

console.log('\n================================================================');
console.log(`  ALL ${passedTests} CREDENTIAL STUFFING TESTS PASSED SUCCESSFULLY!`);
console.log('================================================================\n');
