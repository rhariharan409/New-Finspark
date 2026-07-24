/**
 * Credential Stuffing & Brute Force Detector (Person 2: SK)
 * Main orchestrator module extending the framework's detector pattern.
 * Manages sliding window stores, adaptive historical baseline trackers, and 6 threat rules.
 */

import { IPWindowStore } from './ipWindowStore.js';
import { UserWindowStore } from './userWindowStore.js';
import { PasswordHashWindowStore } from './passwordHashWindowStore.js';
import { BaselineTracker } from './baselineTracker.js';

import { checkBruteForce } from './rules/bruteForceRule.js';
import { checkFailureRatio } from './rules/failureRatioRule.js';
import { checkVelocitySpike } from './rules/velocitySpikeRule.js';
import { checkBotSignature } from './rules/botSignatureRule.js';
import { checkPasswordSpray } from './rules/passwordSprayRule.js';
import { checkCredentialSpray } from './rules/credentialSprayRule.js';
import { DetectorRegistry } from './detectorRegistry.js';

export class CredentialStuffingDetector {
  constructor() {
    this.ipStore = new IPWindowStore(300);
    this.userStore = new UserWindowStore(120);
    this.hashStore = new PasswordHashWindowStore(600);

    this.userBaselineTracker = new BaselineTracker(10);
    this.ipBaselineTracker = new BaselineTracker(10);
  }

  get detectorName() {
    return 'credential_stuffing_detector';
  }

  /**
   * Entry point called by the aggregation engine for EVERY incoming event.
   * - Short-circuits non-login events immediately (returns score 0.0).
   * - Evaluates login events using evaluateLoginEvent and instance stores.
   */
  detect(event, entityState = null, dryRun = false) {
    if (!event) {
      return {
        detector_name: this.detectorName,
        score: 0.0,
        reasons: [],
        evidence_metadata: {}
      };
    }

    const eventType = String(event.event_type || event.eventType || '').toLowerCase().trim();
    const isLogin = (
      eventType === 'login' ||
      eventType === 'login_failed' ||
      eventType === 'eventtype.login'
    );

    if (!isLogin) {
      return {
        detector_name: this.detectorName,
        score: 0.0,
        reasons: [],
        evidence_metadata: {}
      };
    }

    return evaluateLoginEvent(
      event,
      this.ipStore,
      this.userStore,
      this.hashStore,
      this.userBaselineTracker,
      this.ipBaselineTracker,
      dryRun
    );
  }
}

export function evaluateLoginEvent(
  event,
  ipStore = null,
  userStore = null,
  hashStore = null,
  userBaselineTracker = null,
  ipBaselineTracker = null,
  dryRun = false
) {
  const activeIpStore = ipStore || new IPWindowStore(300);
  const activeUserStore = userStore || new UserWindowStore(120);
  const activeHashStore = hashStore || new PasswordHashWindowStore(600);

  const activeUserBt = userBaselineTracker || new BaselineTracker(10);
  const activeIpBt = ipBaselineTracker || new BaselineTracker(10);

  const emptyRuleResult = { score_contribution: 0.0, reason: null, evidence: {} };

  try {
    const eventId = String(event.event_id || event.eventId || '');
    const entityId = String(event.entity_id || event.user_id || event.userId || '');
    const ipAddress = event.ip_address || event.ipAddress || null;
    const timestamp = event.timestamp || event.event_timestamp || new Date();
    const payload = (event.payload || event.metadata || {});

    const loginSuccess = Boolean(payload.login_success || payload.loginSuccess || false);
    const passwordHash = payload.password_hash || payload.passwordHash || null;
    const userAgent = payload.user_agent || payload.userAgent || null;

    // 1. UPDATE STORES (SKIP IF DRY RUN)
    if (!dryRun) {
      if (ipAddress) {
        try {
          activeIpStore.recordEvent(ipAddress, entityId, timestamp, loginSuccess);
        } catch (e) {
          console.error('[IPStore Update Error]', e.message);
        }
      }

      try {
        activeUserStore.recordEvent(entityId, ipAddress || '', timestamp, loginSuccess);
      } catch (e) {
        console.error('[UserStore Update Error]', e.message);
      }

      if (passwordHash) {
        try {
          activeHashStore.recordEvent(passwordHash, entityId, timestamp);
        } catch (e) {
          console.error('[HashStore Update Error]', e.message);
        }
      }
    }

    // 2. FETCH CURRENT STORE STATE
    let ipState = { timestamps: [], failed_count: 0, success_count: 0, target_users_set: new Set() };
    if (ipAddress) {
      try {
        ipState = activeIpStore.getIPState(ipAddress, timestamp);
      } catch (e) {
        console.error('[IPStore Fetch Error]', e.message);
      }
    }

    let userState = { timestamps: [], failed_count: 0, source_ips_set: new Set() };
    try {
      userState = activeUserStore.getUserState(entityId, timestamp);
    } catch (e) {
      console.error('[UserStore Fetch Error]', e.message);
    }

    let passwordHashState = { timestamps: [], distinct_users_set: new Set() };
    if (passwordHash) {
      try {
        passwordHashState = activeHashStore.getHashState(passwordHash, timestamp);
      } catch (e) {
        console.error('[HashStore Fetch Error]', e.message);
      }
    }

    // 3. EVALUATE INDEPENDENT RULES
    let resultR2 = emptyRuleResult;
    try {
      resultR2 = checkBruteForce(userState, entityId, activeUserBt);
    } catch (e) {
      console.error('[Rule R2 Error]', e.message);
    }

    let resultR3 = emptyRuleResult;
    if (ipAddress) {
      try {
        resultR3 = checkFailureRatio(ipState, ipAddress);
      } catch (e) {
        console.error('[Rule R3 Error]', e.message);
      }
    }

    let resultR4 = emptyRuleResult;
    if (ipAddress) {
      try {
        resultR4 = checkVelocitySpike(ipState, ipAddress, timestamp);
      } catch (e) {
        console.error('[Rule R4 Error]', e.message);
      }
    }

    let resultR5 = emptyRuleResult;
    try {
      resultR5 = checkBotSignature(userAgent);
    } catch (e) {
      console.error('[Rule R5 Error]', e.message);
    }

    let resultR6 = emptyRuleResult;
    try {
      resultR6 = checkPasswordSpray(passwordHashState, passwordHash);
    } catch (e) {
      console.error('[Rule R6 Error]', e.message);
    }

    // 4. EVALUATE CORROBORATION-GATED RULE
    let resultR1 = emptyRuleResult;
    if (ipAddress) {
      try {
        const failureRatioFired = (resultR3.score_contribution || 0) > 0;
        const velocitySpikeFired = (resultR4.score_contribution || 0) > 0;
        resultR1 = checkCredentialSpray(
          ipState,
          ipAddress,
          failureRatioFired,
          velocitySpikeFired,
          activeIpBt
        );
      } catch (e) {
        console.error('[Rule R1 Error]', e.message);
      }
    }

    // 5. UPDATE BASELINE TRACKERS (POST-DETECTION, SKIP IF DRY RUN)
    if (!dryRun) {
      try {
        const currentFailed = userState.failed_count || 0;
        activeUserBt.update(entityId, currentFailed);
      } catch (e) {
        console.error('[User Baseline Update Error]', e.message);
      }

      if (ipAddress) {
        try {
          const currentDistinct = (ipState.target_users_set || new Set()).size;
          activeIpBt.update(ipAddress, currentDistinct);
        } catch (e) {
          console.error('[IP Baseline Update Error]', e.message);
        }
      }
    }

    // 6. AGGREGATE RESULTS
    const allResults = [resultR1, resultR2, resultR3, resultR4, resultR5, resultR6];
    const rawScore = allResults.reduce((sum, res) => sum + (res.score_contribution || 0.0), 0.0);
    const totalScore = Math.min(rawScore, 100.0);

    const firedReasons = allResults.map(r => r.reason).filter(Boolean);
    const rulesFiredCount = allResults.filter(r => (r.score_contribution || 0) > 0).length;

    const combinedEvidence = {};
    for (const res of allResults) {
      if (res.evidence && typeof res.evidence === 'object') {
        Object.assign(combinedEvidence, res.evidence);
      }
    }

    combinedEvidence.total_score = totalScore;
    combinedEvidence.rules_fired_count = rulesFiredCount;
    combinedEvidence.ip_address = ipAddress;
    combinedEvidence.entity_id = entityId;
    combinedEvidence.event_id = eventId;

    return {
      detector_name: 'credential_stuffing_detector',
      score: totalScore,
      reasons: firedReasons,
      evidence_metadata: combinedEvidence
    };

  } catch (e) {
    console.error('[evaluateLoginEvent Critical Failure]', e);
    return {
      detector_name: 'credential_stuffing_detector',
      score: 0.0,
      reasons: [],
      evidence_metadata: {
        error: e.message,
        total_score: 0.0,
        rules_fired_count: 0
      }
    };
  }
}

// Instantiate and register singleton detector instance at module import
export const credentialStuffingDetector = new CredentialStuffingDetector();
DetectorRegistry.register(credentialStuffingDetector);
