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
export function createUserEntity(userData) {
  const timestamp = userData.created_at || new Date().toISOString();
  const status = userData.account_status || ACCOUNT_STATUS.ACTIVE;
  const name = userData.full_name || userData.fullName || '';

  return {
    user_id: userData.user_id || 'usr_' + Date.now() + '_' + Math.random().toString(36).substring(2, 7),
    account_id: userData.account_id || 'TURTLE-' + Math.floor(1000000000 + Math.random() * 9000000000),
    full_name: name.trim(),
    email: (userData.email || '').toLowerCase().trim(),
    phone: (userData.phone || '').trim(),
    password_hash: userData.password_hash || '',
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
