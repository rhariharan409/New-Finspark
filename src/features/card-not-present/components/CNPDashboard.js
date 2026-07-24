/**
 * CNP Dashboard Composite View (JS Runtime)
 */

import { renderSimulationModeSelector } from './SimulationModeSelector.js';
import { renderDecisionCard } from './DecisionCard.js';
import { renderFraudTimeline } from './FraudTimeline.js';
import { renderReasonList } from './ReasonList.js';
import { renderRiskScoreGauge } from './RiskScoreGauge.js';
import { renderTelemetryPanel } from './TelemetryPanel.js';
import { renderTransactionFeaturesPanel } from './TransactionFeaturesPanel.js';
import { renderCardPaymentForm } from './CardPaymentForm.js';

export function renderCNPDashboard(data, activeScenarioId) {
  return `
    <div class="cnp-dashboard-container" style="max-width: 1050px; margin: 0 auto; padding: 0.5rem;">
      
      <!-- Top Title Header -->
      <div style="background: linear-gradient(135deg, #005994 0%, #0072bb 100%); color: #ffffff; padding: 1.5rem 1.75rem; border-radius: 8px; margin-bottom: 1.5rem; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem; box-shadow: 0 4px 15px rgba(0, 89, 148, 0.2);">
        <div>
          <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.25rem;">
            <span style="background: rgba(255, 255, 255, 0.2); color: #d0e4ff; border: 1px solid rgba(255, 255, 255, 0.3); font-size: 0.72rem; font-weight: 700; padding: 0.2rem 0.6rem; border-radius: 20px;">
              BANK OF MAHARASHTRA • CYBERSECURITY TELEMETRY + AI RISK ENGINE
            </span>
          </div>
          <h1 style="margin: 0; font-size: 1.6rem; font-weight: 800; color: #ffffff;">
            Card Not Present (CNP) Fraud Detection
          </h1>
          <p style="margin: 0.35rem 0 0 0; color: #ebf2ff; font-size: 0.88rem;">
            Real-time simulation analyzing transaction behaviour & cybersecurity signals before payment approval
          </p>
        </div>
        <a href="dashboard.html" class="btn btn-outline" style="color: #ffffff; border-color: rgba(255, 255, 255, 0.4); background: transparent; font-size: 0.85rem; font-weight: 700;">
          ← Back to Main Dashboard
        </a>
      </div>

      <!-- 1. Preset Scenario Selector -->
      ${renderSimulationModeSelector(activeScenarioId)}

      <!-- 2. Main Animated Decision Card -->
      ${renderDecisionCard(data.riskResult)}

      <!-- 3. Form & Telemetry Two-Column Grid -->
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 1.25rem; align-items: start;">
        <div>
          <!-- Card Payment Input Form -->
          ${renderCardPaymentForm(data.transaction)}

          <!-- Risk Gauge Meter -->
          ${renderRiskScoreGauge(data.riskResult)}
        </div>

        <div>
          <!-- Cybersecurity Telemetry Panel -->
          ${renderTelemetryPanel(data.telemetry)}

          <!-- Transaction Behavioral Features -->
          ${renderTransactionFeaturesPanel(data.transaction)}
        </div>
      </div>

      <!-- 4. Fraud Event Timeline (Main Feature) -->
      ${renderFraudTimeline(data.timeline)}

      <!-- 5. Explainable AI Reason List -->
      ${renderReasonList(data.riskResult)}

    </div>
  `;
}
