/**
 * Card Not Present (CNP) Fraud Detection Express Module
 * Exposes REST API routes for CNP simulation & risk evaluation.
 */

import express from 'express';
import { cnpService } from './services/cnpService.js';
import { scenarioGenerator } from './scenarioGenerator.js';

const router = express.Router();

/**
 * Evaluate CNP Transaction & Telemetry API
 * POST /api/card-not-present/evaluate
 */
router.post('/evaluate', (req, res) => {
  try {
    const { transaction, telemetry } = req.body;
    const result = cnpService.runSimulation(transaction || {}, telemetry || {});

    return res.status(200).json({
      success: true,
      message: 'CNP fraud evaluation completed successfully.',
      data: result
    });
  } catch (error) {
    console.error('CNP Evaluation Error:', error);
    return res.status(500).json({
      success: false,
      message: 'Failed to complete CNP risk evaluation.',
      error: error.message
    });
  }
});

/**
 * Get Available Preset Demo Scenarios API
 * GET /api/card-not-present/scenarios
 */
router.get('/scenarios', (req, res) => {
  try {
    const scenarios = scenarioGenerator.getAllScenarios();
    return res.status(200).json({
      success: true,
      count: scenarios.length,
      scenarios
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: 'Failed to retrieve CNP scenarios.'
    });
  }
});

/**
 * Get Specific Scenario API
 * GET /api/card-not-present/scenarios/:id
 */
router.get('/scenarios/:id', (req, res) => {
  try {
    const scenario = scenarioGenerator.getScenarioById(req.params.id);
    return res.status(200).json({
      success: true,
      scenario
    });
  } catch (error) {
    return res.status(404).json({
      success: false,
      message: 'Scenario not found.'
    });
  }
});

export const cardNotPresentModule = {
  name: 'card-not-present',
  router
};
