/**
 * Database & Data Management Area
 * Exports storage repository abstractions for Bank of Turtles.
 */

import { userRepository } from './userRepository.js';
import { sessionRepository } from './sessionRepository.js';

export {
  userRepository,
  sessionRepository
};

export const dbModule = {
  name: 'db',
  userRepository,
  sessionRepository
};
