/**
 * User Service
 * Business Logic Service handling user identity logic, uniqueness checks, and repository interactions.
 */

import { userRepository } from '../db/userRepository.js';
import { toSafeUser } from '../models/userModel.js';

export const userService = {
  /**
   * Check if an email address exists
   */
  async emailExists(email) {
    if (!email) return false;
    return await userRepository.emailExists(email);
  },

  /**
   * Create a new user identity record
   */
  async createUser(userData) {
    if (!userData || !userData.email) {
      throw new Error('User creation requires a valid email address.');
    }

    // Check email uniqueness before persisting
    const exists = await userRepository.emailExists(userData.email);
    if (exists) {
      throw new Error(`Email '${userData.email}' is already registered.`);
    }

    const createdUser = await userRepository.createUser(userData);
    return toSafeUser(createdUser);
  },

  /**
   * Retrieve user by email (returns safe user object without password_hash)
   */
  async findUserByEmail(email, returnRawHash = false) {
    const user = await userRepository.findUserByEmail(email);
    if (!user) return null;
    return returnRawHash ? user : toSafeUser(user);
  },

  /**
   * Retrieve user by public bank account ID
   */
  async findUserByAccountId(accountId) {
    const user = await userRepository.findUserByAccountId(accountId);
    if (!user) return null;
    return toSafeUser(user);
  },

  /**
   * Retrieve user by internal user ID
   */
  async findUserById(userId) {
    const user = await userRepository.findUserById(userId);
    if (!user) return null;
    return toSafeUser(user);
  }
};
