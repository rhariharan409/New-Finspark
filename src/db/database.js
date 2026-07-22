/**
 * Central Database Connection & Relational Schema Layer
 * Bank of Turtles
 * Uses Node's built-in SQLite relational database engine (node:sqlite)
 */

import { DatabaseSync } from 'node:sqlite';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { createUserEntity } from '../models/userModel.js';
import { createSessionEntity } from '../models/sessionModel.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DB_PATH = path.join(__dirname, 'bank_of_turtles.db');
const USERS_JSON = path.join(__dirname, 'users.json');
const SESSIONS_JSON = path.join(__dirname, 'sessions.json');

// Initialize SQLite Relational Database Connection
export const db = new DatabaseSync(DB_PATH);

// Enable Foreign Key Constraints
db.exec('PRAGMA foreign_keys = ON;');

/**
 * Initialize Relational Database Schema & Tables
 */
function initTables() {
  // Table 1: users
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      user_id TEXT PRIMARY KEY,
      account_id TEXT UNIQUE NOT NULL,
      full_name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      phone TEXT,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL,
      account_status TEXT NOT NULL DEFAULT 'active'
    );
  `);

  // Table 2: sessions
  db.exec(`
    CREATE TABLE IF NOT EXISTS sessions (
      session_id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      login_time TEXT NOT NULL,
      logout_time TEXT,
      session_duration_seconds INTEGER,
      session_status TEXT NOT NULL DEFAULT 'active',
      FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
    );
  `);
}

/**
 * Idempotent Data Migration from legacy JSON files into SQLite Relational Tables
 */
function migrateLegacyJsonData() {
  // 1. Migrate Legacy Users JSON -> users Table
  if (fs.existsSync(USERS_JSON)) {
    try {
      const rawUsers = fs.readFileSync(USERS_JSON, 'utf-8');
      const usersList = JSON.parse(rawUsers || '[]');

      const insertUserStmt = db.prepare(`
        INSERT OR IGNORE INTO users (
          user_id, account_id, full_name, email, phone, password_hash, created_at, account_status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `);

      for (const u of usersList) {
        const userEntity = createUserEntity({
          user_id: u.user_id || u.id,
          account_id: u.account_id || u.accountNumber,
          full_name: u.full_name || u.fullName,
          email: u.email,
          phone: u.phone || '',
          password_hash: u.password_hash || u.passwordHash || '',
          created_at: u.created_at || u.createdAt,
          account_status: u.account_status || u.accountStatus || 'active'
        });

        insertUserStmt.run(
          userEntity.user_id,
          userEntity.account_id,
          userEntity.full_name,
          userEntity.email,
          userEntity.phone,
          userEntity.password_hash,
          userEntity.created_at,
          userEntity.account_status
        );
      }
    } catch (err) {
      console.error('Legacy Users JSON Migration Error:', err.message);
    }
  }

  // 2. Migrate Legacy Sessions JSON -> sessions Table
  if (fs.existsSync(SESSIONS_JSON)) {
    try {
      const rawSessions = fs.readFileSync(SESSIONS_JSON, 'utf-8');
      const sessionsList = JSON.parse(rawSessions || '[]');

      const insertSessionStmt = db.prepare(`
        INSERT OR IGNORE INTO sessions (
          session_id, user_id, login_time, logout_time, session_duration_seconds, session_status
        ) VALUES (?, ?, ?, ?, ?, ?)
      `);

      for (const s of sessionsList) {
        const sessionEntity = createSessionEntity(s);
        insertSessionStmt.run(
          sessionEntity.session_id,
          sessionEntity.user_id,
          sessionEntity.login_time,
          sessionEntity.logout_time,
          sessionEntity.session_duration_seconds,
          sessionEntity.session_status
        );
      }
    } catch (err) {
      console.error('Legacy Sessions JSON Migration Error:', err.message);
    }
  }
}

// Perform Initialization & Automated Idempotent Migration
initTables();
migrateLegacyJsonData();
