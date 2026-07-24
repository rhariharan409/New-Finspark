/**
 * Welford Algorithm Precision & Order Verification
 */
import assert from 'node:assert/strict';
import { BaselineTracker } from '../src/security/credential_stuffing/baselineTracker.js';

console.log('--- WELFORD ALGORITHM VERIFICATION ---');
const tracker = new BaselineTracker(10);
const entityId = 'test_welford_entity';

// Feed 1..10
for (let i = 1; i <= 10; i++) {
  tracker.update(entityId, i);
}

const stats = tracker.getStats(entityId);
console.log(`Computed Mean: ${stats.mean}`);
console.log(`Computed VarianceSum: ${stats.varianceSum}`);
console.log(`Computed StdDev: ${stats.stdDev}`);

assert.equal(stats.count, 10);
assert.ok(Math.abs(stats.mean - 5.5) < 1e-10, `Expected mean 5.5, got ${stats.mean}`);
assert.ok(Math.abs(stats.stdDev - 2.8722813232690143) < 1e-10, `Expected stdDev ~2.87228, got ${stats.stdDev}`);

console.log('[PASS] Welford algorithm calculation produces exact double precision mean=5.5, stdDev=2.8722813232690143');
