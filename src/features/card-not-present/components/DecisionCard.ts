/**
 * Decision Card Component
 * Large animated status card displaying final decision recommendation
 */

import { RiskEvaluationResult } from '../types/cnpTypes.js';
import { RISK_DECISION_CONFIG } from '../constants.js';

export function renderDecisionCard(riskResult: RiskEvaluationResult): string {
  const config = RISK_DECISION_CONFIG[riskResult.recommendation];

  return `
    <div 
      class="cnp-decision-card"
      style="
        margin-bottom: 1.5rem; 
        padding: 1.5rem; 
        border-radius: 12px; 
        background: ${config.bgColor}; 
        border: 2px solid ${config.borderColor}; 
        box-shadow: 0 10px 25px -5px ${config.color}20;
        animation: pulseBorder 2s infinite ease-in-out;
      "
    >
      <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 1rem;">
        <div style="display: flex; align-items: center; gap: 1rem;">
          <div style="font-size: 2.75rem; line-height: 1;">
            ${config.icon}
          </div>
          <div>
            <span style="font-size: 0.75rem; font-weight: 800; text-transform: uppercase; letter-spacing: 0.8px; color: ${config.color};">
              FINAL AI ENGINE RECOMMENDATION
            </span>
            <h2 style="margin: 0.2rem 0 0 0; color: #0f172a; font-size: 1.6rem; font-weight: 800;">
              ${config.label}
            </h2>
            <p style="margin: 0.35rem 0 0 0; color: #475569; font-size: 0.9rem; max-width: 600px;">
              ${config.description}
            </p>
          </div>
        </div>

        <div style="text-align: right; background: #ffffff; padding: 0.85rem 1.25rem; border-radius: 10px; border: 1px solid ${config.borderColor}; min-width: 140px;">
          <div style="font-size: 0.75rem; color: #64748b; font-weight: 700; text-transform: uppercase;">Risk Score</div>
          <div style="font-size: 1.8rem; font-weight: 900; color: ${config.color}; leading: 1;">
            ${riskResult.score} <span style="font-size: 0.9rem; font-weight: 600; color: #64748b;">/ 100</span>
          </div>
          <div style="font-size: 0.72rem; font-weight: 700; color: ${config.color}; text-transform: uppercase; margin-top: 0.1rem;">
            ${riskResult.riskLevel} RISK
          </div>
        </div>
      </div>
    </div>
  `;
}
