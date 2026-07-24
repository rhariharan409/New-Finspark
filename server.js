/**
 * Bank of Turtles - Main Server Entry Point
 * Express server configuration with session management, static page serving, authentication, banking, behavioral telemetry, user baseline, and risk decision engine APIs.
 */

import 'dotenv/config';
import express from 'express';
import session from 'express-session';
import path from 'path';
import { fileURLToPath } from 'url';

import { authModule } from './src/auth/index.js';
import { sessionModule } from './src/session/index.js';
import { bankingModule } from './src/banking/index.js';
import { telemetryModule } from './src/telemetry/index.js';
import { baselineModule } from './src/baseline/index.js';
import { riskModule } from './src/risk/index.js';
import { analystModule } from './src/analyst/index.js';
import { cardNotPresentModule } from './src/features/card-not-present/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// Body parser middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session management middleware
app.use(session({
  secret: process.env.SESSION_SECRET || 'bank_of_turtles_secure_session_secret_key_2026',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 1000 * 60 * 60 * 2, // 2 hours
    httpOnly: true,
    sameSite: 'lax'
  }
}));

// Static files middleware
app.use(express.static(path.join(__dirname, 'public')));
app.use('/src', express.static(path.join(__dirname, 'src')));

// Mount API routes
app.use('/api/auth', authModule.router);
app.use('/api/transactions', bankingModule.router);
app.use('/api/telemetry', telemetryModule.router);
app.use('/api/baseline', baselineModule.router);
app.use('/api/risk', riskModule.router);
app.use('/api/analyst', analystModule.router);
app.use('/api/card-not-present', cardNotPresentModule.router);

// Protected API Route example
app.get('/api/protected/dashboard-data', sessionModule.requireAuth, (req, res) => {
  res.json({
    success: true,
    data: {
      notice: 'Welcome to your secure Bank of Turtles dashboard.',
      securityStatus: 'Active'
    }
  });
});

// Fallback route for static hosting
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start Server
app.listen(PORT, () => {
  console.log(`====================================================`);
  console.log(`  Bank of Turtles Server running at http://localhost:${PORT}`);
  console.log(`====================================================`);
});
