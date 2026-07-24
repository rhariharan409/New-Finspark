/**
 * Scenario Generator Service for CNP Fraud Detection
 * Provides instant access to pre-configured hackathon demo scenarios.
 */

import { SimulationScenario } from './types/cnpTypes.js';
import { SIMULATION_SCENARIOS } from './mock/scenarios.js';

export class ScenarioGenerator {
  public getAllScenarios(): SimulationScenario[] {
    return SIMULATION_SCENARIOS;
  }

  public getScenarioById(scenarioId: string): SimulationScenario {
    const found = SIMULATION_SCENARIOS.find(s => s.id === scenarioId);
    return found || SIMULATION_SCENARIOS[0];
  }
}

export const scenarioGenerator = new ScenarioGenerator();
