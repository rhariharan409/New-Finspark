import crypto from 'crypto';
import dotenv from 'dotenv';

dotenv.config();

// Salt from environment variables, fallback for tests or missing env
const salt = process.env.ENTITY_HASH_SALT || 'bank_of_turtles_default_mule_salt_2026';

/**
 * Computes a salted SHA-256 HMAC hash of a string value.
 * @param {string} value
 * @returns {string}
 */
export function hashToken(value) {
  if (!value) return '';
  const cleanVal = String(value).trim().toLowerCase();
  return crypto
    .createHmac('sha256', salt)
    .update(cleanVal)
    .digest('hex');
}
