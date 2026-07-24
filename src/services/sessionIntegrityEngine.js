/**
 * FINSPARK - Session Integrity Engine (Account Takeover / ATO Protection)
 * Captures real client environment baselines upon authentication and continuously validates
 * subsequent requests against database records to detect Account Takeover (ATO).
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
 * Helper to extract IP and Geolocation details, giving priority to real client environment payloads
 */
function extractRequestGeoDetails(req) {
  const clientEnv = req.body?.clientEnv || {};
  const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket?.remoteAddress || req.ip || '127.0.0.1';
  const userAgent = clientEnv.userAgent || req.headers['user-agent'] || 'Mozilla/5.0';
  const language = clientEnv.language || req.headers['accept-language']?.split(',')[0] || 'en-US';
  const timezone = clientEnv.timezone || req.headers['x-timezone'] || 'Asia/Kolkata';

  const country = req.headers['x-country'] || clientEnv.country || 'Unknown';
  const region = req.headers['x-region'] || clientEnv.region || 'Unknown';
  const city = req.headers['x-city'] || clientEnv.city || 'Unknown';
  const deviceFingerprint = clientEnv.deviceFingerprint || req.headers['x-device-fingerprint'] || `FP-DEV-${Buffer.from(userAgent + ip).toString('base64').substring(0, 12)}`;
  const screenResolution = clientEnv.screenResolution || req.headers['x-screen-res'] || '1920x1080';

  const parsed = parseUserAgent(userAgent);
  const browserName = clientEnv.browserName || parsed.browserName;
  const browserVersion = clientEnv.browserVersion || parsed.browserVersion;
  const operatingSystem = clientEnv.operatingSystem || parsed.os;

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
    operatingSystem,
    screenResolution
  };
}

export const sessionIntegrityEngine = {
  /**
   * 1. CREATE TRUSTED SESSION PROFILE UPON LOGIN & PERSIST TO DB
   */
  async createTrustedSessionProfile({ sessionId, userId, accountId, req, preAuthRiskContext }) {
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
      lastSeenTimestamp: now.toISOString(),
      preAuthRiskContext: preAuthRiskContext || { preAuth: { credentialStuffingScore: 0 }, combinedScore: 0 }
    };

    trustedSessionProfiles.set(sessionId, trustedProfile);

    // Persist to Supabase trusted_session_profiles table
    try {
      const { error } = await supabase.from('trusted_session_profiles').upsert([{
        session_id: sessionId,
        user_id: userId,
        account_id: trustedProfile.accountId,
        device_fingerprint: details.deviceFingerprint,
        browser_name: details.browserName,
        browser_version: details.browserVersion,
        operating_system: details.operatingSystem,
        user_agent: details.userAgent,
        ip_address: details.ipAddress,
        country: details.country,
        region: details.region,
        city: details.city,
        timezone: details.timezone,
        language: details.language,
        screen_resolution: details.screenResolution,
        login_timestamp: now.toISOString()
      }]);
      if (error) {
        console.error('Supabase trusted_session_profiles upsert error:', error.message);
      } else {
        console.log(`[SessionIntegrityEngine] Saved trusted session profile ${sessionId} to Supabase.`);
      }
    } catch (err) {
      console.error('Session profile save exception:', err.message);
    }

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

    // If not in memory, query Supabase trusted_session_profiles table
    if (!trusted) {
      try {
        const { data } = await supabase.from('trusted_session_profiles').select('*').eq('session_id', sessionId).single();
        if (data) {
          trusted = {
            sessionId: data.session_id,
            userId: data.user_id,
            accountId: data.account_id || userId,
            deviceId: `DEV-${(data.device_fingerprint || '').substring(0, 8)}`,
            deviceFingerprint: data.device_fingerprint,
            browserName: data.browser_name,
            browserVersion: data.browser_version,
            operatingSystem: data.operating_system,
            userAgent: data.user_agent,
            ipAddress: data.ip_address,
            country: data.country,
            region: data.region,
            city: data.city,
            timezone: data.timezone,
            language: data.language,
            screenResolution: data.screen_resolution,
            loginTimestamp: data.login_timestamp,
            sessionExpiry: new Date(new Date(data.login_timestamp).getTime() + 2 * 3600 * 1000).toISOString(),
            requestCount: 1,
            lastSeenTimestamp: new Date().toISOString()
          };
          trustedSessionProfiles.set(sessionId, trusted);
        }
      } catch (e) {}
    }

    // Fallback baseline if no DB record found
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
    return this.evaluateProfilesComparison(trusted, current);
  },

  /**
   * Helper to perform comparison and rule score calculation
   */
  async evaluateProfilesComparison(trusted, current) {
    const triggeredRules = [];
    
    // CORRELATION: Start from the pre-auth score, not zero
    const preAuthCarryover = trusted.preAuthRiskContext?.combinedScore || 0;
    let totalRiskScore = preAuthCarryover;

    if (preAuthCarryover > 0) {
      triggeredRules.push({
        ruleId: 'PRE_AUTH_RISK_CARRYOVER',
        ruleName: 'Pre-Authentication Risk Carryover',
        weight: preAuthCarryover,
        severity: preAuthCarryover >= 50 ? 'HIGH' : 'MEDIUM',
        description: `Session inherited ${preAuthCarryover} risk points from pre-auth credential stuffing analysis.`,
        evidence: `${trusted.preAuthRiskContext?.preAuth?.failedAttemptsBeforeSuccess || 0} failed login attempts preceded this session.`
      });
    }

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
      triggeredRules.push({ ...rule, evidence: `Device fingerprint '${current.deviceFingerprint}' differs from trusted baseline '${trusted.deviceFingerprint}'` });
    }

    // Compare Country (+35)
    const isUnknownCountry = (current.country || 'unknown').toLowerCase() === 'unknown' || (trusted.country || 'unknown').toLowerCase() === 'unknown';
    const isCountryMatched = isUnknownCountry || (current.country || '').toLowerCase() === (trusted.country || '').toLowerCase();
    if (!isCountryMatched) {
      const rule = SESSION_INTEGRITY_RULES.find(r => r.ruleId === 'COUNTRY_CHANGED');
      totalRiskScore += rule.weight;
      triggeredRules.push({ ...rule, evidence: `Country changed from '${trusted.country}' to '${current.country}'` });
    }

    // Compare Browser (+20)
    const isBrowserMatched = (current.browserName || '').toLowerCase() === (trusted.browserName || '').toLowerCase();
    if (!isBrowserMatched) {
      const rule = SESSION_INTEGRITY_RULES.find(r => r.ruleId === 'BROWSER_CHANGED');
      totalRiskScore += rule.weight;
      triggeredRules.push({ ...rule, evidence: `Browser changed from '${trusted.browserName}' to '${current.browserName}'` });
    }

    // Compare Operating System (+20)
    const isOSMatched = (current.operatingSystem || '').toLowerCase() === (trusted.operatingSystem || '').toLowerCase();
    if (!isOSMatched) {
      const rule = SESSION_INTEGRITY_RULES.find(r => r.ruleId === 'OS_CHANGED');
      totalRiskScore += rule.weight;
      triggeredRules.push({ ...rule, evidence: `OS changed from '${trusted.operatingSystem}' to '${current.operatingSystem}'` });
    }

    // Compare City / Location (+15)
    const isUnknownCity = (current.city || 'unknown').toLowerCase() === 'unknown' || (trusted.city || 'unknown').toLowerCase() === 'unknown';
    const isLocationMatched = isUnknownCity || (current.city || '').toLowerCase() === (trusted.city || '').toLowerCase();
    if (!isLocationMatched && isCountryMatched) {
      const rule = SESSION_INTEGRITY_RULES.find(r => r.ruleId === 'LOCATION_CHANGED');
      totalRiskScore += rule.weight;
      triggeredRules.push({ ...rule, evidence: `City changed from '${trusted.city}' to '${current.city}'` });
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

    // Full Evidence Record
    const evidenceRecord = {
      sessionId: trusted.sessionId,
      userId: trusted.userId,
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

    sessionIntegrityEvidence.set(trusted.sessionId, evidenceRecord);

    // Persist suspicious evidence to risk_decisions table for analyst portal
    if (action !== 'ALLOW') {
      try {
        await riskRepository.createRiskDecision({
          transaction_id: `ATO-${Date.now().toString(36).toUpperCase()}`,
          user_id: trusted.userId,
          session_id: trusted.sessionId,
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
   * 3. SIMULATE ATO ATTACK (TEST MODE FOR PROJECT DEMO)
   */
  async simulateATOAttack({ sessionId, attackPreset, customParams }) {
    let trusted = trustedSessionProfiles.get(sessionId);
    if (!trusted) {
      // Query DB for trusted profile
      try {
        const { data } = await supabase.from('trusted_session_profiles').select('*').eq('session_id', sessionId).single();
        if (data) {
          trusted = {
            sessionId: data.session_id,
            userId: data.user_id,
            accountId: data.account_id,
            deviceId: `DEV-${(data.device_fingerprint || '').substring(0, 8)}`,
            deviceFingerprint: data.device_fingerprint,
            browserName: data.browser_name,
            browserVersion: data.browser_version,
            operatingSystem: data.operating_system,
            userAgent: data.user_agent,
            ipAddress: data.ip_address,
            country: data.country,
            region: data.region,
            city: data.city,
            timezone: data.timezone,
            language: data.language,
            screenResolution: data.screen_resolution,
            loginTimestamp: data.login_timestamp,
            sessionExpiry: new Date(Date.now() + 2 * 3600 * 1000).toISOString()
          };
        }
      } catch (e) {}
    }

    if (!trusted) {
      trusted = {
        sessionId: sessionId || 'SES-882341',
        userId: 'USR-001',
        accountId: 'ACC-001',
        deviceId: 'Windows Laptop',
        deviceFingerprint: 'FP-CANVAS-TRUSTED-123',
        browserName: 'Chrome',
        browserVersion: '126.0',
        operatingSystem: 'Windows 11',
        userAgent: 'Mozilla/5.0 (Windows NT 10.0)',
        ipAddress: '49.207.54.12',
        country: 'India',
        region: 'Tamil Nadu',
        city: 'Chennai',
        timezone: 'Asia/Kolkata',
        language: 'en-US',
        screenResolution: '1920x1080',
        loginTimestamp: new Date().toISOString(),
        sessionExpiry: new Date(Date.now() + 2 * 3600 * 1000).toISOString()
      };
    }

    let simulatedCurrent = { ...trusted };

    if (attackPreset === 'BROWSER_SWITCH') {
      simulatedCurrent.browserName = 'Firefox';
      simulatedCurrent.browserVersion = '125.0';
      simulatedCurrent.operatingSystem = 'Linux';
      simulatedCurrent.deviceFingerprint = 'FP-CANVAS-HIJACKED-998';
    } else if (attackPreset === 'CROSS_COUNTRY_HIJACK') {
      simulatedCurrent.deviceFingerprint = 'FP-CANVAS-ATTACKER-DE';
      simulatedCurrent.browserName = 'Firefox';
      simulatedCurrent.browserVersion = '125.0';
      simulatedCurrent.operatingSystem = 'Linux';
      simulatedCurrent.ipAddress = '185.220.101.5';
      simulatedCurrent.country = 'Germany';
      simulatedCurrent.region = 'Berlin';
      simulatedCurrent.city = 'Berlin';
      simulatedCurrent.timezone = 'Europe/Berlin';
    } else if (attackPreset === 'SESSION_REPLAY') {
      simulatedCurrent.deviceFingerprint = 'FP-CANVAS-REPLAY-889';
      simulatedCurrent.ipAddress = '103.22.180.1';
      simulatedCurrent.country = 'Russia';
      simulatedCurrent.city = 'Moscow';
    } else if (customParams) {
      simulatedCurrent = { ...simulatedCurrent, ...customParams };
    }

    const evaluation = await this.evaluateProfilesComparison(trusted, simulatedCurrent);
    return evaluation;
  },

  /**
   * 4. GET EVIDENCE RECORD FOR A SESSION ID
   */
  getEvidenceForSession(sessionId) {
    if (!sessionId) return null;
    return sessionIntegrityEvidence.get(sessionId) || null;
  },

  /**
   * 5. GET ALL EVIDENCE RECORDS FOR QUEUE
   */
  getAllEvidenceRecords() {
    return Array.from(sessionIntegrityEvidence.values());
  }
};
