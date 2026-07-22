/**
 * User Behavioral Baseline API Router
 * Implements REST endpoints for querying and recalculating normal user behavioral baselines.
 */

import express from 'express';
import { baselineService } from '../services/baselineService.js';
import { sessionModule } from '../session/index.js';

const router = express.Router();

/**
 * Get Authenticated User Behavioral Baseline API
 * GET /api/baseline
 */
router.get('/', sessionModule.requireAuth, async (req, res) => {
  try {
    // Derive user ID strictly from authenticated session cookie
    const userId = req.session.userId;
    const baseline = await baselineService.getUserBaseline(userId);

    return res.status(200).json({
      success: true,
      baseline
    });

  } catch (error) {
    console.error('Baseline GET Error:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Failed to retrieve behavioral baseline.'
    });
  }
});

/**
 * Recalculate Authenticated User Behavioral Baseline API
 * POST /api/baseline/recalculate
 */
router.post('/recalculate', sessionModule.requireAuth, async (req, res) => {
  try {
    // Derive user ID strictly from authenticated session cookie
    const userId = req.session.userId;
    const updatedBaseline = await baselineService.calculateAndSaveUserBaseline(userId);

    return res.status(200).json({
      success: true,
      message: 'Behavioral baseline recalculated and updated successfully.',
      baseline: updatedBaseline
    });

  } catch (error) {
    console.error('Baseline Recalculate Error:', error.message);
    return res.status(500).json({
      success: false,
      message: error.message || 'Failed to recalculate behavioral baseline.'
    });
  }
});

export const baselineModule = {
  name: 'baseline',
  router
};
