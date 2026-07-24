/**
 * End-to-End Real Integration Test for Credential Stuffing & Behavioral Auth Engine
 * Uses real store instances and realistic sequential login events with spaced timestamps.
 */

import assert from 'node:assert/strict';
import { CredentialStuffingDetector } from '../src/security/credential_stuffing/credentialStuffingDetector.js';
import { SCENARIO_DEFINITIONS } from '../src/security/credential_stuffing/scenarioDefinitions.js';

console.log('================================================================');
console.log('  RUNNING REAL E2E INTEGRATION TEST (REAL STORES & TIMESTAMPS)');
console.log('================================================================\n');

// SCENARIO 1: CREDENTIAL_STUFFING_SPRAY
console.log('--- SCENARIO 1: CREDENTIAL_STUFFING_SPRAY ---');
{
  const detector = new CredentialStuffingDetector();
  const rawScenario = SCENARIO_DEFINITIONS.CREDENTIAL_STUFFING_SPRAY;
  const baseTime = new Date('2026-07-23T10:00:00Z').getTime();

  let finalResult = null;
  rawScenario.events.forEach((evt, index) => {
    // Add realistic spaced timestamps (e.g. 2 seconds apart)
    const eventWithTimestamp = {
      ...evt,
      timestamp: new Date(baseTime + index * 2000)
    };
    finalResult = detector.detect(eventWithTimestamp);
  });

  console.log('Literal DetectorResult for CREDENTIAL_STUFFING_SPRAY:');
  console.log(JSON.stringify(finalResult, null, 2));

  // Expectations check:
  // R1 (credential spray) must fire
  const hasR1 = finalResult.reasons.some(r => r.includes('Credential spray'));
  // R3 (failure ratio) must fire
  const hasR3 = finalResult.reasons.some(r => r.includes('Automated failure pattern'));
  // R5 (bot signature) must NOT fire because standard Chrome UA is used
  const hasR5 = finalResult.reasons.some(r => r.includes('Bot signature'));

  console.log(`\nVerifications:`);
  console.log(`- R1 Credential Spray Fired: ${hasR1 ? 'YES' : 'NO'}`);
  console.log(`- R3 Failure Ratio Fired:    ${hasR3 ? 'YES' : 'NO'}`);
  console.log(`- R5 Bot Signature Fired:    ${hasR5 ? 'YES' : 'NO'} (Expected: NO for Chrome UA)`);

  assert.ok(hasR1, 'Expected R1 Credential Spray to fire');
  assert.ok(hasR3, 'Expected R3 Failure Ratio to fire');
  assert.equal(hasR5, false, 'R5 Bot Signature should NOT fire for valid Chrome UA');
}

console.log('\n----------------------------------------------------------------');
// SCENARIO 2: BRUTE_FORCE_SINGLE_ACCOUNT
console.log('--- SCENARIO 2: BRUTE_FORCE_SINGLE_ACCOUNT ---');
{
  const detector = new CredentialStuffingDetector();
  const rawScenario = SCENARIO_DEFINITIONS.BRUTE_FORCE_SINGLE_ACCOUNT;
  const baseTime = new Date('2026-07-23T10:00:00Z').getTime();

  let finalResult = null;
  rawScenario.events.forEach((evt, index) => {
    const eventWithTimestamp = {
      ...evt,
      timestamp: new Date(baseTime + index * 3000)
    };
    finalResult = detector.detect(eventWithTimestamp);
  });

  console.log('Literal DetectorResult for BRUTE_FORCE_SINGLE_ACCOUNT:');
  console.log(JSON.stringify(finalResult, null, 2));

  // Expectations check:
  // R2 (account brute force) must fire (7 failures >= threshold 5.0)
  const hasR2 = finalResult.reasons.some(r => r.includes('Account brute force'));

  console.log(`\nVerifications:`);
  console.log(`- R2 Account Brute Force Fired: ${hasR2 ? 'YES' : 'NO'}`);

  assert.ok(hasR2, 'Expected R2 Account Brute Force to fire');
}

console.log('\n----------------------------------------------------------------');
// SCENARIO 3: PASSWORD_SPRAY_DISTRIBUTED
console.log('--- SCENARIO 3: PASSWORD_SPRAY_DISTRIBUTED ---');
{
  const detector = new CredentialStuffingDetector();
  const rawScenario = SCENARIO_DEFINITIONS.PASSWORD_SPRAY_DISTRIBUTED;
  const baseTime = new Date('2026-07-23T10:00:00Z').getTime();

  let finalResult = null;
  const allResults = [];
  rawScenario.events.forEach((evt, index) => {
    const eventWithTimestamp = {
      ...evt,
      timestamp: new Date(baseTime + index * 5000)
    };
    finalResult = detector.detect(eventWithTimestamp);
    allResults.push(finalResult);
  });

  console.log('Literal DetectorResult for PASSWORD_SPRAY_DISTRIBUTED (Final Event 6):');
  console.log(JSON.stringify(finalResult, null, 2));

  // Expectations check:
  // R6 (password spray) must fire
  const hasR6 = finalResult.reasons.some(r => r.includes('Password spraying'));
  // R1 (credential spray per IP) must NOT fire because max users per IP is 2 (< threshold of 3)
  const hasR1 = finalResult.reasons.some(r => r.includes('Credential spray'));

  console.log(`\nVerifications:`);
  console.log(`- R6 Password Spray Fired:       ${hasR6 ? 'YES' : 'NO'}`);
  console.log(`- R1 Credential Spray Fired:     ${hasR1 ? 'YES' : 'NO'} (Expected: NO, only 2 users per IP)`);

  assert.ok(hasR6, 'Expected R6 Password Spray to fire');
  assert.equal(hasR1, false, 'R1 Credential Spray should NOT fire per-IP (only 2 distinct users per IP)');
}

console.log('\n----------------------------------------------------------------');
// SCENARIO 4: HIGH_VELOCITY_SPIKE
console.log('--- SCENARIO 4: HIGH_VELOCITY_SPIKE ---');
{
  const detector = new CredentialStuffingDetector();
  const rawScenario = SCENARIO_DEFINITIONS.HIGH_VELOCITY_SPIKE;
  const baseTime = new Date('2026-07-23T10:00:00Z').getTime();

  let finalResult = null;
  rawScenario.events.forEach((evt, index) => {
    // 25 events spaced 1 second apart (all within 60 seconds)
    const eventWithTimestamp = {
      ...evt,
      timestamp: new Date(baseTime + index * 1000)
    };
    finalResult = detector.detect(eventWithTimestamp);
  });

  console.log('Literal DetectorResult for HIGH_VELOCITY_SPIKE (Final Event 25):');
  console.log(JSON.stringify(finalResult, null, 2));

  // Expectations check:
  // R4 (velocity spike) must fire (25 events in 60s > threshold 20)
  const hasR4 = finalResult.reasons.some(r => r.includes('Velocity anomaly'));

  console.log(`\nVerifications:`);
  console.log(`- R4 Velocity Spike Fired: ${hasR4 ? 'YES' : 'NO'}`);

  assert.ok(hasR4, 'Expected R4 Velocity Spike to fire for >20 events in 60 seconds');
}

console.log('\n----------------------------------------------------------------');
// SCENARIO 5: BOT_AUTOMATION_ATTACK
console.log('--- SCENARIO 5: BOT_AUTOMATION_ATTACK ---');
{
  const detector = new CredentialStuffingDetector();
  const rawScenario = SCENARIO_DEFINITIONS.BOT_AUTOMATION_ATTACK;
  const baseTime = new Date('2026-07-23T10:00:00Z').getTime();

  let finalResult = null;
  rawScenario.events.forEach((evt, index) => {
    const eventWithTimestamp = {
      ...evt,
      timestamp: new Date(baseTime + index * 1000)
    };
    finalResult = detector.detect(eventWithTimestamp);
  });

  console.log('Literal DetectorResult for BOT_AUTOMATION_ATTACK:');
  console.log(JSON.stringify(finalResult, null, 2));

  // Expectations check:
  // R5 (bot signature) must fire (User-Agent: python-requests/2.28.0)
  const hasR5 = finalResult.reasons.some(r => r.includes('Bot signature'));

  console.log(`\nVerifications:`);
  console.log(`- R5 Bot Signature Fired: ${hasR5 ? 'YES' : 'NO'}`);

  assert.ok(hasR5, 'Expected R5 Bot Signature to fire for automation tool User-Agent');
}

console.log('\n================================================================');
console.log('  ALL 5 E2E INTEGRATION TEST SCENARIOS PASSED WITH EXACT EXPECTATIONS!');
console.log('================================================================\n');

