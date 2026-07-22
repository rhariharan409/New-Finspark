/**
 * Password Security Service
 * Handles password hashing and verification using bcryptjs.
 */

import bcrypt from 'bcryptjs';

const SALT_ROUNDS = 10;

export const passwordService = {
  /**
   * Hashes a plain-text password securely.
   * Never stores or logs the raw password.
   */
  async hashPassword(password) {
    if (!password || typeof password !== 'string') {
      throw new Error('Password security error: Password must be a non-empty string.');
    }
    return await bcrypt.hash(password, SALT_ROUNDS);
  },

  /**
   * Verifies a plain-text password against a stored hash.
   * Returns true if match, false if invalid or on failure.
   */
  async verifyPassword(password, passwordHash) {
    if (!password || !passwordHash) {
      return false;
    }
    try {
      return await bcrypt.compare(password, passwordHash);
    } catch (error) {
      console.error('Password verification error handled safely.');
      return false;
    }
  }
};
