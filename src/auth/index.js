/**
 * Authentication Module Router for Bank of Turtles
 * Implements user signup, login, session validation, and logout APIs.
 */

import express from 'express';
import { userService } from '../services/userService.js';
import { passwordService } from '../security/passwordService.js';
import { sessionService } from '../services/sessionService.js';
import { telemetryService } from '../services/telemetryService.js';
import { sessionModule } from '../session/index.js';
import { sessionIntegrityEngine } from '../services/sessionIntegrityEngine.js';

const router = express.Router();

function toSafeUser(user) {
  if (!user) return null;
  const { password_hash, ...safeUser } = user;
  return safeUser;
}

/**
 * Signup API
 * POST /api/auth/signup
 */
router.post('/signup', async (req, res) => {
  try {
    const { fullName, username, email, phone, password, confirmPassword } = req.body;
    const finalUsername = username || (email ? email.split('@')[0] : '');

    if (!fullName || !email || !password) {
      return res.status(400).json({
        success: false,
        message: 'All required fields must be filled.'
      });
    }

    if (password !== confirmPassword) {
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

    return res.status(201).json({
      success: true,
      message: 'Account created successfully.',
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
 * Login API with Session Creation Integration & Telemetry Logging
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
 * Session Verification API for Normal Users (STRICTLY ISOLATED FROM INTERNAL FRAUD INTELLIGENCE)
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
        const clientDetails = telemetryService.extractClientDetails(req);
        await telemetryService.recordTelemetryEvent({
          userId,
          sessionId,
          eventType: 'logout',
          ipAddress: clientDetails.ipAddress,
          deviceType: clientDetails.deviceType,
          metadata: { logout_time: new Date().toISOString() }
        });
      }
    }

    try {
      await sessionModule.destroySession(req);
    } catch (sErr) {}

    return res.status(200).json({
      success: true,
      message: 'Logout successful.',
      redirectUrl: 'login.html'
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
