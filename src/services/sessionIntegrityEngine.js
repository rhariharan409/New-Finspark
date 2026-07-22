/**
 * FINSPARK - Session Integrity Engine (Account Takeover / ATO Protection)
 * Rule-based Session Integrity Engine that establishes a trusted environment profile at login
 * and continuously evaluates subsequent requests against the baseline to detect session hijacking/ATO.
 */

import { supabase } from '../db/supabaseClient.js';
import { riskRepository } from '../db/riskRepository.js';

// In-Memory Storage Cache for Session Profiles & Evidence
const trustedSessionProfiles = new Map();
const sessionIntegrityEvidence = new Map();

/**
 * Configurable Rule Registry with Weights & Severity Levels
 */
export const SESSION_INTEGRITY_RULES = [
  {
    ruleId: 'EXPIRED_SESSION_REUSED',
    ruleName: 'Expired Session Reused',
    weight: 100,
    severity: 'CRITICAL',
    description: 'Attempt to reuse an expired or terminated session token.'
  },
  {
    ruleId: 'SESSION_REPLAY_DETECTED',
    ruleName: 'Session Replay Attack',
    weight: 80,
    severity: 'CRITICAL',
    description: 'Rapid replay of stolen session identifier across conflicting client signatures.'
  },
  {
    ruleId: 'CONCURRENT_SESSION_DETECTED',
    ruleName: 'Concurrent Session Anomaly',
    weight: 60,
    severity: 'HIGH',
    description: 'Multiple active concurrent sessions detected from different environments.'
  },
  {
    ruleId: 'DEVICE_FINGERPRINT_CHANGED',
    ruleName: 'Device Fingerprint Changed',
    weight: 40,
    severity: 'HIGH',
    description: 'Session device fingerprint does not match login baseline.'
  },
  {
    ruleId: 'COUNTRY_CHANGED',
    ruleName: 'Country / Geo Location Changed',
    weight: 35,
    severity: 'HIGH',
    description: 'Request originated from a different country than login baseline.'
  },
  {
    ruleId: 'BROWSER_CHANGED',
    ruleName: 'Browser Family Changed',
    weight: 20,
    severity: 'MEDIUM',
    description: 'Browser name/family modified mid-session.'
  },
  {
    ruleId: 'OS_CHANGED',
    ruleName: 'Operating System Changed',
    weight: 20,
    severity: 'MEDIUM',
    description: 'Operating system modified mid-session.'
  },
  {
    ruleId: 'LOCATION_CHANGED',
    ruleName: 'City / Region Location Changed',
    weight: 15,
    severity: 'MEDIUM',
    description: 'Request city/region changed during active session.'
  },
  {
    ruleId: 'USER_AGENT_CHANGED',
    ruleName: 'User-Agent Header Changed',
    weight: 15,
    severity: 'MEDIUM',
    description: 'HTTP User-Agent string differs from login profile.'
  },
  {
    ruleId: 'IP_CHANGED',
    ruleName: 'IP Address Changed',
    weight: 10,
    severity: 'LOW',
    description: 'Client IP address changed mid-session.'
  },
  {
    ruleId: 'TIMEZONE_CHANGED',
    ruleName: 'Client Timezone Changed',
    weight: 10,
    severity: 'LOW',
    description: 'Client reported timezone changed.'
  },
  {
    ruleId: 'LANGUAGE_CHANGED',
    ruleName: 'Accept-Language Changed',
    weight: 5,
    severity: 'LOW',
    description: 'HTTP Accept-Language header changed.'
  }
];

/**
 * Helper to parse User Agent into Browser Name, Version, OS
 */
function parseUserAgent(uaString = '') {
  const ua = uaString || '';
  let browserName = 'Chrome';
  let browserVersion = '126.0';
  let os = 'Windows';

  if (ua.includes('Firefox')) {
    browserName = 'Firefox';
    browserVersion = ua.split('Firefox/')[1]?.split(' ')[0] || '125.0';
  } else if (ua.includes('Edg')) {
    browserName = 'Edge';
    browserVersion = ua.split('Edg/')[1]?.split(' ')[0] || '124.0';
  } else if (ua.includes('Safari') && !ua.includes('Chrome')) {
    browserName = 'Safari';
    browserVersion = ua.split('Version/')[1]?.split(' ')[0] || '17.0';
  } else if (ua.includes('Chrome')) {
    browserName = 'Chrome';
    browserVersion = ua.split('Chrome/')[1]?.split(' ')[0] || '126.0';
  }

  if (ua.includes('Windows')) os = 'Windows 11';
  else if (ua.includes('Mac OS')) os = 'macOS';
  else if (ua.includes('Linux')) os = 'Linux';
  else if (ua.includes('Android')) os = 'Android';
  else if (ua.includes('iPhone') || ua.includes('iPad')) os = 'iOS';

  return { browserName, browserVersion, os };
}

/**
 * Helper to extract IP and Geolocation details
 */
function extractRequestGeoDetails(req) {
  const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket?.remoteAddress || req.ip || '127.0.0.1';
  const userAgent = req.headers['user-agent'] || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)';
  const language = req.headers['accept-language']?.split(',')[0] || 'en-US';
  const timezone = req.headers['x-timezone'] || req.body?.timezone || 'Asia/Kolkata';

  // Extract simulated/custom headers or defaults
  const country = req.headers['x-country'] || 'India';
  const region = req.headers['x-region'] || 'Tamil Nadu';
  const city = req.headers['x-city'] || 'Chennai';
  const deviceFingerprint = req.headers['x-device-fingerprint'] || req.body?.deviceFingerprint || `FP-${Buffer.from(userAgent + ip).toString('base64').substring(0, 16)}`;
  const screenResolution = req.headers['x-screen-res'] || req.body?.screenResolution || '1920x1080';

  const { browserName, browserVersion, os } = parseUserAgent(userAgent);

  return {
    ipAddress: ip,
    userAgent,
    language,
    timezone,
    country,
    region,
    city,
    deviceFingerprint,
    deviceId: req.headers['x-device-id'] || `DEV-${deviceFingerprint.substring(0, 8)}`,
    browserName,
    browserVersion,
    operatingSystem: os,
    screenResolution
  };
}

export const sessionIntegrityEngine = {
  /**
   * 1. CREATE TRUSTED SESSION PROFILE UPON LOGIN
   */
  async createTrustedSessionProfile({ sessionId, userId, accountId, req }) {
    if (!sessionId || !userId) return null;

    const details = extractRequestGeoDetails(req);
    const now = new Date();
    const expiry = new Date(now.getTime() + 2 * 3600 * 1000); // 2 hours

    const trustedProfile = {
      sessionId,
      userId,
      accountId: accountId || userId,
      deviceId: details.deviceId,
      deviceFingerprint: details.deviceFingerprint,
      browserName: details.browserName,
      browserVersion: details.browserVersion,
      operatingSystem: details.operatingSystem,
      userAgent: details.userAgent,
      ipAddress: details.ipAddress,
      country: details.country,
      region: details.region,
      city: details.city,
      timezone: details.timezone,
      language: details.language,
      screenResolution: details.screenResolution,
      loginTimestamp: now.toISOString(),
      sessionExpiry: expiry.toISOString(),
      requestCount: 1,
      lastSeenTimestamp: now.toISOString()
    };

    trustedSessionProfiles.set(sessionId, trustedProfile);

    // Persist to Supabase if table exists (gracefully handle fallback)
    try {
      await supabase.from('session_profiles').upsert([{
        session_id: sessionId,
        user_id: userId,
        account_id: trustedProfile.accountId,
        device_fingerprint: details.deviceFingerprint,
        browser_name: details.browserName,
        operating_system: details.operatingSystem,
        user_agent: details.userAgent,
        ip_address: details.ipAddress,
        country: details.country,
        city: details.city,
        timezone: details.timezone,
        login_timestamp: now.toISOString()
      }]);
    } catch (err) {}

    return trustedProfile;
  },

  /**
   * 2. VALIDATE CURRENT REQUEST AGAINST TRUSTED SESSION PROFILE
   */
  async validateRequestSession(req) {
    const sessionId = req.session ? req.session.sessionId : null;
    const userId = req.session ? req.session.userId : null;

    if (!sessionId || !userId) {
      return {
        action: 'ALLOW',
        riskScore: 0,
        riskLevel: 'LOW',
        evidence: null
      };
    }

    let trusted = trustedSessionProfiles.get(sessionId);

    // Fallback: Create dynamic baseline if not in memory
    if (!trusted) {
      const details = extractRequestGeoDetails(req);
      trusted = {
        sessionId,
        userId,
        accountId: req.session?.user?.account_id || userId,
        deviceId: details.deviceId,
        deviceFingerprint: details.deviceFingerprint,
        browserName: details.browserName,
        browserVersion: details.browserVersion,
        operatingSystem: details.operatingSystem,
        userAgent: details.userAgent,
        ipAddress: details.ipAddress,
        country: details.country,
        region: details.region,
        city: details.city,
        timezone: details.timezone,
        language: details.language,
        screenResolution: details.screenResolution,
        loginTimestamp: new Date().toISOString(),
        sessionExpiry: new Date(Date.now() + 2 * 3600 * 1000).toISOString(),
        requestCount: 1,
        lastSeenTimestamp: new Date().toISOString()
      };
      trustedSessionProfiles.set(sessionId, trusted);
    }

    trusted.requestCount++;
    trusted.lastSeenTimestamp = new Date().toISOString();

    const current = extractRequestGeoDetails(req);
    const triggeredRules = [];
    let totalRiskScore = 0;

    // Check Expired Session
    if (new Date() > new Date(trusted.sessionExpiry)) {
      const rule = SESSION_INTEGRITY_RULES.find(r => r.ruleId === 'EXPIRED_SESSION_REUSED');
      totalRiskScore += rule.weight;
      triggeredRules.push({ ...rule, evidence: `Session expired at ${trusted.sessionExpiry}` });
    }

    // Compare Device Fingerprint (+40)
    const isDeviceMatched = current.deviceFingerprint === trusted.deviceFingerprint;
    if (!isDeviceMatched) {
      const rule = SESSION_INTEGRITY_RULES.find(r => r.ruleId === 'DEVICE_FINGERPRINT_CHANGED');
      totalRiskScore += rule.weight;
      triggeredRules.push({ ...rule, evidence: `Device fingerprint '${current.deviceFingerprint}' differs from trusted '${trusted.deviceFingerprint}'` });
    }

    // Compare Country (+35)
    const isCountryMatched = current.country.toLowerCase() === trusted.country.toLowerCase();
    if (!isCountryMatched) {
      const rule = SESSION_INTEGRITY_RULES.find(r => r.ruleId === 'COUNTRY_CHANGED');
      totalRiskScore += rule.weight;
      triggeredRules.push({ ...rule, evidence: `Country changed from '${trusted.country}' to '${current.country}'` });
    }

    // Compare Browser (+20)
    const isBrowserMatched = current.browserName.toLowerCase() === trusted.browserName.toLowerCase();
    if (!isBrowserMatched) {
      const rule = SESSION_INTEGRITY_RULES.find(r => r.ruleId === 'BROWSER_CHANGED');
      totalRiskScore += rule.weight;
      triggeredRules.push({ ...rule, evidence: `Browser changed from '${trusted.browserName}' to '${current.browserName}'` });
    }

    // Compare Operating System (+20)
    const isOSMatched = current.operatingSystem.toLowerCase() === trusted.operatingSystem.toLowerCase();
    if (!isOSMatched) {
      const rule = SESSION_INTEGRITY_RULES.find(r => r.ruleId === 'OS_CHANGED');
      totalRiskScore += rule.weight;
      triggeredRules.push({ ...rule, evidence: `OS changed from '${trusted.operatingSystem}' to '${current.operatingSystem}'` });
    }

    // Compare City / Location (+15)
    const isLocationMatched = current.city.toLowerCase() === trusted.city.toLowerCase();
    if (!isLocationMatched && isCountryMatched) {
      const rule = SESSION_INTEGRITY_RULES.find(r => r.ruleId === 'LOCATION_CHANGED');
      totalRiskScore += rule.weight;
      triggeredRules.push({ ...rule, evidence: `Location city changed from '${trusted.city}' to '${current.city}'` });
    }

    // Compare User Agent (+15)
    const isUAMatched = current.userAgent === trusted.userAgent;
    if (!isUAMatched && isBrowserMatched && isOSMatched) {
      const rule = SESSION_INTEGRITY_RULES.find(r => r.ruleId === 'USER_AGENT_CHANGED');
      totalRiskScore += rule.weight;
      triggeredRules.push({ ...rule, evidence: `User-Agent modified mid-session.` });
    }

    // Compare IP Address (+10)
    const isIPMatched = current.ipAddress === trusted.ipAddress;
    if (!isIPMatched) {
      const rule = SESSION_INTEGRITY_RULES.find(r => r.ruleId === 'IP_CHANGED');
      totalRiskScore += rule.weight;
      triggeredRules.push({ ...rule, evidence: `IP address changed from '${trusted.ipAddress}' to '${current.ipAddress}'` });
    }

    // Compare Timezone (+10)
    const isTimezoneMatched = current.timezone === trusted.timezone;
    if (!isTimezoneMatched) {
      const rule = SESSION_INTEGRITY_RULES.find(r => r.ruleId === 'TIMEZONE_CHANGED');
      totalRiskScore += rule.weight;
      triggeredRules.push({ ...rule, evidence: `Client timezone changed from '${trusted.timezone}' to '${current.timezone}'` });
    }

    // Compare Language (+5)
    const isLangMatched = current.language === trusted.language;
    if (!isLangMatched) {
      const rule = SESSION_INTEGRITY_RULES.find(r => r.ruleId === 'LANGUAGE_CHANGED');
      totalRiskScore += rule.weight;
      triggeredRules.push({ ...rule, evidence: `Language changed from '${trusted.language}' to '${current.language}'` });
    }

    // Calculate Decision Thresholds
    const finalScore = Math.min(100, totalRiskScore);
    let riskLevel = 'LOW';
    let action = 'ALLOW';

    if (finalScore >= 90) {
      riskLevel = 'CRITICAL';
      action = 'BLOCK';
    } else if (finalScore >= 60) {
      riskLevel = 'HIGH';
      action = 'STEP-UP';
    } else if (finalScore >= 30) {
      riskLevel = 'MEDIUM';
      action = 'MONITOR';
    }

    // Attribute Comparison Summary
    const attributeComparison = {
      deviceFingerprint: isDeviceMatched ? 'Matched' : 'Changed',
      browser: isBrowserMatched ? 'Matched' : 'Changed',
      operatingSystem: isOSMatched ? 'Matched' : 'Changed',
      userAgent: isUAMatched ? 'Matched' : 'Changed',
      ipAddress: isIPMatched ? 'Matched' : 'Changed',
      location: isLocationMatched ? 'Matched' : 'Changed',
      country: isCountryMatched ? 'Matched' : 'Changed',
      timezone: isTimezoneMatched ? 'Matched' : 'Changed',
      language: isLangMatched ? 'Matched' : 'Changed'
    };

    // Full Analyst Evidence Record
    const evidenceRecord = {
      sessionId,
      userId,
      accountId: trusted.accountId,
      detectionReason: 'Account Takeover (ATO)',
      riskScore: finalScore,
      riskLevel,
      action,
      decision: action,
      timestamp: new Date().toISOString(),
      originalProfile: {
        deviceId: trusted.deviceId,
        deviceFingerprint: trusted.deviceFingerprint,
        browser: `${trusted.browserName} ${trusted.browserVersion}`,
        operatingSystem: trusted.operatingSystem,
        userAgent: trusted.userAgent,
        ipAddress: trusted.ipAddress,
        location: `${trusted.city}, ${trusted.region}, ${trusted.country}`,
        country: trusted.country,
        timezone: trusted.timezone,
        language: trusted.language
      },
      currentProfile: {
        deviceId: current.deviceId,
        deviceFingerprint: current.deviceFingerprint,
        browser: `${current.browserName} ${current.browserVersion}`,
        operatingSystem: current.operatingSystem,
        userAgent: current.userAgent,
        ipAddress: current.ipAddress,
        location: `${current.city}, ${current.region}, ${current.country}`,
        country: current.country,
        timezone: current.timezone,
        language: current.language
      },
      attributeComparison,
      triggeredRules
    };

    sessionIntegrityEvidence.set(sessionId, evidenceRecord);

    // Persist suspicious evidence to risk_decisions table for analyst portal
    if (action !== 'ALLOW') {
      try {
        await riskRepository.createRiskDecision({
          transaction_id: `ATO-${Date.now().toString(36).toUpperCase()}`,
          user_id: userId,
          session_id: sessionId,
          risk_score: finalScore,
          risk_level: riskLevel,
          decision: action,
          risk_factors: triggeredRules.map(r => r.ruleName),
          baseline_snapshot: {
            reason: 'Account Takeover (ATO)',
            evidence: evidenceRecord
          }
        });
      } catch (err) {}
    }

    return {
      action,
      riskScore: finalScore,
      riskLevel,
      evidence: evidenceRecord
    };
  },

  /**
   * 3. GET EVIDENCE RECORD FOR A SESSION ID
   */
  getEvidenceForSession(sessionId) {
    if (!sessionId) return null;
    return sessionIntegrityEvidence.get(sessionId) || null;
  },

  /**
   * 4. GET ALL SUSPICIOUS SESSIONS FOR ANALYST QUEUE
   */
  getAllEvidenceRecords() {
    return Array.from(sessionIntegrityEvidence.values());
  }
};
