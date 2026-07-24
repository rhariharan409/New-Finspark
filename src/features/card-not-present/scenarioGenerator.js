/**
 * Scenario Generator Service for CNP Fraud Detection (JS Runtime)
 */

import { SIMULATION_SCENARIOS } from './mock/scenarios.js';

export class ScenarioGenerator {
  getAllScenarios() {
    return SIMULATION_SCENARIOS;
  }

  getScenarioById(scenarioId) {
    const found = SIMULATION_SCENARIOS.find(s => s.id === scenarioId);
    return found || SIMULATION_SCENARIOS[0];
  }
}

export const scenarioGenerator = new ScenarioGenerator();
