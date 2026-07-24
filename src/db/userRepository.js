/**
 * User Repository (Supabase PostgreSQL Integration)
 * Data Access Layer executing queries against the Supabase users table.
 */

import { supabase } from './supabaseClient.js';
import { createUserEntity } from '../models/userModel.js';

// In-memory balance cache initialized with ₹10,00,000.00 (10 Lakhs baseline) per user
const userBalancesMap = new Map();

export const userRepository = {
  /**
   * Retrieves user's total available balance (default 10 Lakhs baseline)
   */
  getUserBalance(userId) {
    if (!userId) return 1000000.00;
    const cleanId = String(userId).trim();
    if (!userBalancesMap.has(cleanId)) {
      userBalancesMap.set(cleanId, 1000000.00); // Baseline ₹10,00,000.00
    }
    return userBalancesMap.get(cleanId);
  },

  /**
   * Updates user's total account balance in memory store
   */
  updateUserBalance(userId, newBalance) {
    if (!userId) return 1000000.00;
    const cleanId = String(userId).trim();
    const rounded = Math.max(0, Math.round(newBalance * 100) / 100);
    userBalancesMap.set(cleanId, rounded);
    return rounded;
  },

  /**
   * Check if an email address already exists in users table
   */
  async emailExists(email) {
    if (!email) return false;
    const cleanEmail = email.toLowerCase().trim();

    const { data, error } = await supabase
      .from('users')
      .select('user_id')
      .ilike('email', cleanEmail)
      .maybeSingle();

    if (error && error.code !== 'PGRST116') {
      console.error('Supabase emailExists error:', error.message);
    }
    return !!data;
  },

  /**
   * Persists a new User row in Supabase users table
   */
  async createUser(userData) {
    const newUser = createUserEntity(userData);

    const { data, error } = await supabase
      .from('users')
      .insert([{
        user_id: newUser.user_id,
        account_id: newUser.account_id,
        full_name: newUser.full_name,
        email: newUser.email,
        phone: newUser.phone,
        password_hash: newUser.password_hash,
        created_at: newUser.created_at,
        account_status: newUser.account_status
      }])
      .select()
      .single();

    if (error) {
      if (error.code === '23505' || error.message.includes('unique constraint')) {
        throw new Error(`User persistence failed: Email '${newUser.email}' or Account ID is already registered.`);
      }
      console.error('Supabase createUser error:', error.message);
      throw new Error(`Failed to create user record: ${error.message}`);
    }

    return data || newUser;
  },

  /**
   * Find user by email address
   */
  async findUserByEmail(email) {
    if (!email) return null;
    const cleanEmail = email.toLowerCase().trim();

    const { data, error } = await supabase
      .from('users')
      .select('*')
      .ilike('email', cleanEmail)
      .maybeSingle();

    if (error && error.code !== 'PGRST116') {
      console.error('Supabase findUserByEmail error:', error.message);
    }

    return data || null;
  },

  /**
   * Find user by public bank account ID
   */
  async findUserByAccountId(accountId) {
    if (!accountId) return null;

    const { data, error } = await supabase
      .from('users')
      .select('*')
      .eq('account_id', accountId.trim())
      .maybeSingle();

    if (error && error.code !== 'PGRST116') {
      console.error('Supabase findUserByAccountId error:', error.message);
    }

    return data || null;
  },

  /**
   * Find user by internal user ID
   */
  async findUserById(userId) {
    if (!userId) return null;

    const { data, error } = await supabase
      .from('users')
      .select('*')
      .eq('user_id', userId.trim())
      .maybeSingle();

    if (error && error.code !== 'PGRST116') {
      console.error('Supabase findUserById error:', error.message);
    }

    return data || null;
  }
};
