/**
 * Data Migration Script: Local SQLite / JSON -> Supabase PostgreSQL
 * Bank of Turtles
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { DatabaseSync } from 'node:sqlite';
import { supabase } from './supabaseClient.js';
import { createUserEntity } from '../models/userModel.js';
import { createSessionEntity } from '../models/sessionModel.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const DB_PATH = path.join(__dirname, 'bank_of_turtles.db');
const USERS_JSON = path.join(__dirname, 'users.json');
const SESSIONS_JSON = path.join(__dirname, 'sessions.json');

async function runMigration() {
  console.log('🚀 Starting Data Migration to Supabase PostgreSQL...');

  const usersToMigrate = new Map();
  const sessionsToMigrate = new Map();

  // 1. Read from SQLite bank_of_turtles.db if present
  if (fs.existsSync(DB_PATH)) {
    try {
      const db = new DatabaseSync(DB_PATH);
      const sqlUsers = db.prepare('SELECT * FROM users').all();
      const sqlSessions = db.prepare('SELECT * FROM sessions').all();

      for (const u of sqlUsers) {
        usersToMigrate.set(u.user_id, createUserEntity(u));
      }
      for (const s of sqlSessions) {
        sessionsToMigrate.set(s.session_id, createSessionEntity(s));
      }
      console.log(`📦 Loaded ${sqlUsers.length} users & ${sqlSessions.length} sessions from SQLite database.`);
    } catch (err) {
      console.warn('Could not read SQLite database:', err.message);
    }
  }

  // 2. Read from legacy JSON files as fallback
  if (fs.existsSync(USERS_JSON)) {
    try {
      const raw = fs.readFileSync(USERS_JSON, 'utf-8');
      const jsonUsers = JSON.parse(raw || '[]');
      for (const u of jsonUsers) {
        const entity = createUserEntity({
          user_id: u.user_id || u.id,
          account_id: u.account_id || u.accountNumber,
          full_name: u.full_name || u.fullName,
          email: u.email,
          phone: u.phone || '',
          password_hash: u.password_hash || u.passwordHash || '',
          created_at: u.created_at || u.createdAt,
          account_status: u.account_status || u.accountStatus || 'active'
        });
        if (!usersToMigrate.has(entity.user_id)) {
          usersToMigrate.set(entity.user_id, entity);
        }
      }
    } catch (err) {}
  }

  if (fs.existsSync(SESSIONS_JSON)) {
    try {
      const raw = fs.readFileSync(SESSIONS_JSON, 'utf-8');
      const jsonSessions = JSON.parse(raw || '[]');
      for (const s of jsonSessions) {
        const entity = createSessionEntity(s);
        if (!sessionsToMigrate.has(entity.session_id)) {
          sessionsToMigrate.set(entity.session_id, entity);
        }
      }
    } catch (err) {}
  }

  const userList = Array.from(usersToMigrate.values());
  const sessionList = Array.from(sessionsToMigrate.values());

  console.log(`⚡ Migrating ${userList.length} unique users to Supabase users table...`);

  if (userList.length > 0) {
    const { data: userUpsertData, error: userErr } = await supabase
      .from('users')
      .upsert(userList, { onConflict: 'user_id' });

    if (userErr) {
      console.error('❌ User Migration Error:', userErr.message);
    } else {
      console.log('✅ Users migrated successfully.');
    }
  }

  console.log(`⚡ Migrating ${sessionList.length} unique sessions to Supabase sessions table...`);

  if (sessionList.length > 0) {
    const { data: sessionUpsertData, error: sessionErr } = await supabase
      .from('sessions')
      .upsert(sessionList, { onConflict: 'session_id' });

    if (sessionErr) {
      console.error('❌ Session Migration Error:', sessionErr.message);
    } else {
      console.log('✅ Sessions migrated successfully.');
    }
  }

  console.log('🎉 Data Migration Complete!');
}

runMigration().catch(err => {
  console.error('Migration process failed:', err);
});
