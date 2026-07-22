/**
 * User Data Model
 * Reusable User entity definition and status enumerations for Bank of Turtles.
 */

export const ACCOUNT_STATUS = Object.freeze({
  ACTIVE: 'active',
  SUSPENDED: 'suspended'
});

/**
 * Creates a formatted User entity adhering to system field naming standards
 */
export function createUserEntity({
  user_id,
  account_id,
  full_name,
  email,
  phone,
  password_hash,
  created_at,
  account_status
}) {
  const timestamp = created_at || new Date().toISOString();
  const status = account_status || ACCOUNT_STATUS.ACTIVE;

  return {
    user_id: user_id || 'usr_' + Date.now() + '_' + Math.random().toString(36).substring(2, 7),
    account_id: account_id || 'TURTLE-' + Math.floor(1000000000 + Math.random() * 9000000000),
    full_name: (full_name || '').trim(),
    email: (email || '').toLowerCase().trim(),
    phone: (phone || '').trim(),
    password_hash: password_hash || '',
    created_at: timestamp,
    account_status: status
  };
}

/**
 * Returns a safe representation of the user object without sensitive security hashes
 */
export function toSafeUser(user) {
  if (!user) return null;
  const { password_hash, ...safeUser } = user;
  return safeUser;
}
