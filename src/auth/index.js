/**
 * FINSPARK - Authentication API Router
 * User Signup, Login, Session Management, Telemetry Logging, and ATO Session Verification.
 */

import express from 'express';
import { userService } from '../services/userService.js';
import { passwordService } from '../security/passwordService.js';
import { sessionModule } from '../session/index.js';
import { sessionService } from '../services/sessionService.js';
import { telemetryService } from '../services/telemetryService.js';
import { sessionIntegrityEngine } from '../services/sessionIntegrityEngine.js';
import { supabase } from '../db/supabaseClient.js';
import { riskRepository } from '../db/riskRepository.js';

const router = express.Router();

function toSafeUser(user) {
  if (!user) return null;
  const { password_hash, ...safe } = user;
  return safe;
}

/**
 * Signup API
 * POST /api/auth/signup
 */
router.post('/signup', async (req, res) => {
  try {
    const { email, password, confirmPassword, fullName, phone, username } = req.body;
    const finalUsername = (username || email || '').trim().toLowerCase();

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Email address and password are required.'
      });
    }

    if (confirmPassword !== undefined && password !== confirmPassword) {
      return res.status(400).json({
        success: false,
        message: 'Passwords do not match.'
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 6 characters long.'
      });
    }

    const exists = await userService.emailExists(email);
    if (exists) {
      return res.status(409).json({
        success: false,
        message: 'Email address is already registered.'
      });
    }

    const password_hash = await passwordService.hashPassword(password);
    const newUser = await userService.createUser({
      full_name: fullName || req.body.full_name || '',
      fullName: fullName || req.body.full_name || '',
      username: finalUsername,
      email,
      phone,
      password_hash
    });

    const safeUser = toSafeUser(newUser);
    const activeSession = await sessionService.createSessionForUser(newUser.user_id);

    sessionModule.setSessionUser(req, safeUser);
    req.session.sessionId = activeSession.session_id;

    return res.status(201).json({
      success: true,
      message: 'Account registered successfully.',
      redirectUrl: 'dashboard.html',
      user: safeUser
    });

  } catch (error) {
    console.error('Signup error:', error.message);
    return res.status(500).json({
      success: false,
      message: 'An error occurred while creating your account.'
    });
  }
});

/**
 * Login API with Session Creation & Trusted Environment Logging
 * POST /api/auth/login
 */
router.post('/login', async (req, res) => {
  try {
    const identifier = req.body.identifier || req.body.email || req.body.username;
    const password = req.body.password;

    if (!identifier || !password) {
      return res.status(400).json({
        success: false,
        message: 'Please enter your email and password.'
      });
    }

    const trimmedIdentifier = identifier.trim();
    const rawUser = (await userService.findUserByEmail(trimmedIdentifier, true)) ||
                    (await userService.findUserByAccountId(trimmedIdentifier, true)) ||
                    (await userService.findUserById(trimmedIdentifier, true));

    if (!rawUser || !rawUser.password_hash) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password.'
      });
    }

    if (rawUser.account_status === 'suspended') {
      return res.status(403).json({
        success: false,
        message: 'Account is suspended. Please contact customer support.'
      });
    }

    const isMatch = await passwordService.verifyPassword(password, rawUser.password_hash);
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password.'
      });
    }

    const safeUser = toSafeUser(rawUser);
    const activeSession = await sessionService.createSessionForUser(rawUser.user_id);

    sessionModule.setSessionUser(req, safeUser);
    req.session.sessionId = activeSession.session_id;

    // Create Trusted Session Profile in Session Integrity Engine for ATO Detection
    try {
      await sessionIntegrityEngine.createTrustedSessionProfile({
        sessionId: activeSession.session_id,
        userId: rawUser.user_id,
        accountId: rawUser.account_id,
        req
      });
    } catch (eErr) {
      console.error('Session Integrity Profile Error:', eErr.message);
    }

    const clientDetails = telemetryService.extractClientDetails(req);
    try {
      await telemetryService.recordTelemetryEvent({
        userId: rawUser.user_id,
        sessionId: activeSession.session_id,
        eventType: 'login',
        ipAddress: req.body.ipAddress || clientDetails.ipAddress,
        deviceType: req.body.deviceType || clientDetails.deviceType,
        location: req.body.location || null,
        metadata: { login_time: activeSession.login_time, email: rawUser.email }
      });
    } catch (telemetryError) {
      console.error('Telemetry Login Event Error:', telemetryError.message);
    }

    req.session.save((err) => {
      if (err) console.error('Session save error:', err.message);
      return res.status(200).json({
        success: true,
        message: 'Login successful.',
        redirectUrl: 'dashboard.html',
        user: safeUser
      });
    });

  } catch (error) {
    console.error('Login error:', error.message);
    return res.status(500).json({
      success: false,
      message: 'An error occurred during authentication.'
    });
  }
});

/**
 * Demo API: Session ID Login & Real-Time ATO Specification Cross-Verification
 * POST /api/auth/verify-session-id-login
 */
router.post('/verify-session-id-login', async (req, res) => {
  try {
    const { sessionId, clientEnv } = req.body;
    const cleanSessionId = (sessionId || '').trim();

    if (!cleanSessionId) {
      return res.status(400).json({
        success: false,
        message: 'Session ID is required.'
      });
    }

    // 1. Fetch stored trusted profile from Supabase trusted_session_profiles table
    let trusted = null;
    try {
      const { data } = await supabase
        .from('trusted_session_profiles')
        .select('*')
        .eq('session_id', cleanSessionId)
        .single();
      if (data) trusted = data;
    } catch (e) {}

    // Fallback: Check sessions table for user_id
    let userId = trusted ? trusted.user_id : null;
    if (!userId) {
      try {
        const { data: sessData } = await supabase
          .from('sessions')
          .select('*')
          .eq('session_id', cleanSessionId)
          .single();
        if (sessData) userId = sessData.user_id;
      } catch (e) {}
    }

    if (!userId) {
      return res.status(404).json({
        success: false,
        message: `Session ID '${cleanSessionId}' not found in database.`
      });
    }

    // 2. Fetch User Record
    const rawUser = await userService.findUserById(userId, true);
    if (!rawUser) {
      return res.status(404).json({
        success: false,
        message: 'User account associated with this session was not found.'
      });
    }

    // 3. Extract Current Device Specs from Request
    const incomingEnv = clientEnv || {};
    const currentFingerprint = incomingEnv.deviceFingerprint || req.headers['x-device-fingerprint'] || 'FP-UNKNOWN';
    const currentBrowser = incomingEnv.browserName || 'Unknown';

    // 4. Perform Specification Comparison against DB Baseline
    let isMatch = true;
    let mismatchReasons = [];

    if (trusted) {
      // Compare Device Fingerprint
      if (trusted.device_fingerprint && currentFingerprint !== trusted.device_fingerprint) {
        isMatch = false;
        mismatchReasons.push(`Device Fingerprint Mismatch (Stored DB: ${trusted.device_fingerprint} vs Current: ${currentFingerprint})`);
      }
      // Compare Browser Name
      if (trusted.browser_name && currentBrowser.toLowerCase() !== trusted.browser_name.toLowerCase()) {
        isMatch = false;
        mismatchReasons.push(`Browser Mismatch (Stored DB: ${trusted.browser_name} vs Current: ${currentBrowser})`);
      }
    }

    // 5. Enforce Decision
    if (!isMatch) {
      // Record ATO Decision in DB
      try {
        await riskRepository.createRiskDecision({
          transaction_id: `ATO-${Date.now().toString(36).toUpperCase()}`,
          user_id: userId,
          session_id: cleanSessionId,
          risk_score: 100,
          risk_level: 'CRITICAL',
          decision: 'BLOCK',
          risk_factors: mismatchReasons,
          baseline_snapshot: {
            reason: 'Account Takeover (ATO)',
            mismatch_reasons: mismatchReasons
          }
        });
      } catch (e) {}

      return res.status(403).json({
        success: false,
        matched: false,
        reason: 'ATO_DEVICE_MISMATCH',
        message: `🚫 ACCESS DENIED: Account Takeover (ATO) Detected!\n\nIncoming device specifications do not match the trusted session profile stored in database.\n\n${mismatchReasons.join('\n')}`
      });
    }

    // 6. Legitimate Request - Establish Active Session
    const safeUser = toSafeUser(rawUser);
    sessionModule.setSessionUser(req, safeUser);
    req.session.sessionId = cleanSessionId;

    req.session.save((err) => {
      if (err) console.error('Session save error:', err.message);
      return res.status(200).json({
        success: true,
        matched: true,
        message: '🟢 Session Verified! Device specifications match trusted baseline.',
        redirectUrl: 'dashboard.html',
        user: safeUser
      });
    });

  } catch (error) {
    console.error('Session ID verification login error:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Server error during session ID verification.'
    });
  }
});

/**
 * Session Verification API
 * GET /api/auth/me
 */
router.get('/me', async (req, res) => {
  if (req.session && req.session.userId) {
    const safeUser = await userService.findUserById(req.session.userId);
    if (safeUser) {
      return res.status(200).json({
        success: true,
        authenticated: true,
        user: {
          full_name: safeUser.full_name,
          email: safeUser.email,
          account_id: safeUser.account_id,
          created_at: safeUser.created_at
        }
      });
    }
  }
  return res.status(401).json({
    success: false,
    authenticated: false,
    message: 'No active session.'
  });
});

/**
 * Logout API
 * POST /api/auth/logout
 */
router.post('/logout', async (req, res) => {
  try {
    const sessionId = req.session ? req.session.sessionId : null;
    const userId = req.session ? req.session.userId : null;

    if (sessionId) {
      await sessionService.terminateSession(sessionId, userId);
      if (userId) {
        try {
          await telemetryService.recordTelemetryEvent({
            userId,
            sessionId,
            eventType: 'logout'
          });
        } catch (tErr) {}
      }
    }

    sessionModule.clearSessionUser(req);

    req.session.destroy((err) => {
      if (err) console.error('Session destroy error:', err.message);
      res.clearCookie('connect.sid');
      return res.status(200).json({
        success: true,
        message: 'Logout successful.'
      });
    });

  } catch (error) {
    console.error('Logout error:', error.message);
    return res.status(500).json({
      success: false,
      message: 'An error occurred during logout.'
    });
  }
});

export const authModule = {
  name: 'auth',
  router
};
