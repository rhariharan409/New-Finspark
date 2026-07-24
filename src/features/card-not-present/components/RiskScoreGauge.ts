/**
 * Risk Score Gauge Component
 * Visual 0-100 meter display with risk level color indicators
 */

import { RiskEvaluationResult } from '../types/cnpTypes.js';

export function renderRiskScoreGauge(riskResult: RiskEvaluationResult): string {
  const score = riskResult.score;
  const color = riskResult.colorCode;

  return `
    <div class="account-card" style="margin-bottom: 1.5rem; text-align: center; border-radius: 12px; background: linear-gradient(180deg, #ffffff 0%, #f8fafc 100%);">
      <div style="font-size: 0.85rem; font-weight: 700; color: #64748b; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 0.5rem;">
        AI CNP Risk Score Meter
      </div>

      <!-- Main Circular/Bar Gauge -->
      <div style="position: relative; width: 160px; height: 160px; margin: 0 auto 1rem auto; display: flex; align-items: center; justify-content: center;">
        <svg viewBox="0 0 100 100" style="width: 100%; height: 100%; transform: rotate(-90deg);">
          <!-- Background track -->
          <circle cx="50" cy="50" r="40" stroke="#e2e8f0" stroke-width="10" fill="transparent" />
          <!-- Active score bar -->
          <circle cx="50" cy="50" r="40" stroke="${color}" stroke-width="10" fill="transparent"
            stroke-dasharray="251.2"
            stroke-dashoffset="${251.2 - (251.2 * score) / 100}"
            stroke-linecap="round"
            style="transition: stroke-dashoffset 1s ease-in-out, stroke 0.5s ease;"
          />
        </svg>

        <div style="position: absolute; text-align: center;">
          <div style="font-size: 2.2rem; font-weight: 900; color: ${color}; line-height: 1;">${score}</div>
          <div style="font-size: 0.75rem; color: #64748b; font-weight: 600; margin-top: 0.2rem;">/ 100</div>
        </div>
      </div>

      <!-- Threshold Legend Bar -->
      <div style="max-width: 400px; margin: 0 auto; display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.25rem; font-size: 0.72rem; font-weight: 600; text-align: center; border-radius: 6px; overflow: hidden; padding: 0.25rem; background: #e2e8f0;">
        <div style="background: ${score <= 30 ? '#059669' : '#ffffff'}; color: ${score <= 30 ? '#ffffff' : '#059669'}; padding: 0.35rem 0.1rem; border-radius: 4px;">0-30<br>Approve</div>
        <div style="background: ${score > 30 && score <= 60 ? '#d97706' : '#ffffff'}; color: ${score > 30 && score <= 60 ? '#ffffff' : '#d97706'}; padding: 0.35rem 0.1rem; border-radius: 4px;">31-60<br>OTP</div>
        <div style="background: ${score > 60 && score <= 80 ? '#ea580c' : '#ffffff'}; color: ${score > 60 && score <= 80 ? '#ffffff' : '#ea580c'}; padding: 0.35rem 0.1rem; border-radius: 4px;">61-80<br>Hold</div>
        <div style="background: ${score > 80 ? '#dc2626' : '#ffffff'}; color: ${score > 80 ? '#ffffff' : '#dc2626'}; padding: 0.35rem 0.1rem; border-radius: 4px;">81-100<br>Block</div>
      </div>
    </div>
  `;
}
