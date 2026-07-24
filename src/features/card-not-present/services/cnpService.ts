/**
 * CNP Service orchestrator
 * Combines Telemetry Capture, AI Risk Scoring Engine, and Timeline Generator.
 */

import { CNPTelemetry, CNPTransaction, RiskEvaluationResult, TimelineEvent, SimulationScenario } from '../types/cnpTypes.js';
import { telemetryCollector } from '../telemetryCollector.js';
import { aiRiskEngine } from '../aiRiskEngine.js';
import { timelineGenerator } from '../timelineGenerator.js';
import { scenarioGenerator } from '../scenarioGenerator.js';

export interface CNPSimulationResponse {
  telemetry: CNPTelemetry;
  transaction: CNPTransaction;
  riskResult: RiskEvaluationResult;
  timeline: TimelineEvent[];
}

export class CNPService {
  /**
   * Run complete CNP payment simulation pipeline
   */
  public runSimulation(
    transactionData: Partial<CNPTransaction>,
    telemetryOverride?: Partial<CNPTelemetry>
  ): CNPSimulationResponse {
    // 1. Capture/Simulate Telemetry
    const telemetry = telemetryCollector.collectTelemetry(telemetryOverride);

    // 2. Build complete transaction object with defaults
    const transaction: CNPTransaction = {
      cardNumber: transactionData.cardNumber || '4532 9012 3456 8912',
      cardholderName: transactionData.cardholderName || 'Rahul Sharma',
      expiryDate: transactionData.expiryDate || '08/28',
      cvv: transactionData.cvv || '452',
      amount: parseFloat(String(transactionData.amount || 1450)),
      currency: transactionData.currency || 'INR (₹)',
      merchantName: transactionData.merchantName || 'Flipkart Retail',
      merchantCategory: transactionData.merchantCategory || 'E-Commerce',

      previousAverageAmount: parseFloat(String(transactionData.previousAverageAmount || 1800)),
      isNewMerchant: transactionData.isNewMerchant ?? false,
      isNewCard: transactionData.isNewCard ?? false,
      paymentTimestamp: new Date().toISOString(),
      velocityLastMinute: transactionData.velocityLastMinute ?? 1,
      velocityLastHour: transactionData.velocityLastHour ?? 2,
      beneficiaryHistory: transactionData.beneficiaryHistory || 'Frequent Merchant',
      isInternational: transactionData.isInternational ?? false
    };

    // 3. Evaluate AI Risk Score & Explainability Factors
    const riskResult = aiRiskEngine.evaluateCNPRisk(telemetry, transaction);

    // 4. Generate Dynamic Timeline
    const timeline = timelineGenerator.generateFraudTimeline(telemetry, transaction, riskResult);

    return {
      telemetry,
      transaction,
      riskResult,
      timeline
    };
  }

  /**
   * Load scenario preset
   */
  public loadScenario(scenarioId: string): SimulationScenario {
    return scenarioGenerator.getScenarioById(scenarioId);
  }
}

export const cnpService = new CNPService();
