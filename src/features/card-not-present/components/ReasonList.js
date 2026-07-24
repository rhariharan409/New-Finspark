/**
 * Reason List Component (Explainable AI Panel) (JS Runtime)
 */

export function renderReasonList(riskResult) {
  const positiveRiskFactors = riskResult.reasons.filter(r => r.type === 'POSITIVE_RISK');
  const negativeMitigants = riskResult.reasons.filter(r => r.type === 'NEGATIVE_MITIGANT');

  return `
    <div class="account-card" style="margin-bottom: 1.5rem; border-top: 4px solid #059669; border-radius: 12px;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; border-bottom: 1px solid #f1f5f9; padding-bottom: 0.75rem;">
        <div>
          <h3 style="margin: 0; font-size: 1.15rem; color: #0f172a; display: flex; align-items: center; gap: 0.5rem;">
            <span>🤖</span> Explainable AI Feature Breakdown
          </h3>
          <p style="margin: 0.2rem 0 0 0; color: #64748b; font-size: 0.82rem;">Transparent explanation of feature weights driving the AI risk score</p>
        </div>
        <span class="badge" style="background: #ecfdf5; color: #047857; border: 1px solid #a7f3d0; font-size: 0.75rem;">XAI Transparent Model</span>
      </div>

      <!-- Score Breakdown Header -->
      <div style="background: #f8fafc; padding: 0.85rem 1rem; border-radius: 8px; margin-bottom: 1.25rem; display: flex; justify-content: space-between; align-items: center; border: 1px solid #e2e8f0;">
        <span style="font-weight: 700; color: #0f172a; font-size: 0.95rem;">Evaluated Risk Score</span>
        <span style="font-size: 1.2rem; font-weight: 900; color: ${riskResult.colorCode};">
          ${riskResult.score} / 100
        </span>
      </div>

      <!-- Positive Risk Contributing Factors (+) -->
      <div style="margin-bottom: 1.25rem;">
        <h4 style="margin: 0 0 0.6rem 0; font-size: 0.88rem; color: #dc2626; text-transform: uppercase; letter-spacing: 0.5px; display: flex; align-items: center; gap: 0.4rem;">
          <span>🚨</span> Positive Risk Contributing Factors (+ Score)
        </h4>

        ${positiveRiskFactors.length > 0 ? `
          <div style="display: flex; flex-direction: column; gap: 0.5rem;">
            ${positiveRiskFactors.map(factor => `
              <div style="background: #fef2f2; border: 1px solid #fecaca; padding: 0.75rem; border-radius: 8px; display: flex; justify-content: space-between; align-items: flex-start; gap: 0.75rem;">
                <div>
                  <strong style="color: #991b1b; font-size: 0.88rem; display: block;">✓ ${factor.title}</strong>
                  <span style="color: #475569; font-size: 0.8rem; margin-top: 0.15rem; display: block;">${factor.description}</span>
                </div>
                <span style="background: #dc2626; color: #ffffff; font-weight: 800; font-size: 0.78rem; padding: 0.2rem 0.6rem; border-radius: 20px; white-space: nowrap;">
                  +${factor.weight}
                </span>
              </div>
            `).join('')}
          </div>
        ` : `
          <div style="font-size: 0.82rem; color: #64748b; font-style: italic; background: #f8fafc; padding: 0.6rem; border-radius: 6px;">
            No positive risk factors detected for this transaction.
          </div>
        `}
      </div>

      <!-- Negative Trust Mitigants (-) -->
      <div>
        <h4 style="margin: 0 0 0.6rem 0; font-size: 0.88rem; color: #059669; text-transform: uppercase; letter-spacing: 0.5px; display: flex; align-items: center; gap: 0.4rem;">
          <span>🛡️</span> Trust Mitigants & Behavioral Safety Signals (- Score)
        </h4>

        ${negativeMitigants.length > 0 ? `
          <div style="display: flex; flex-direction: column; gap: 0.5rem;">
            ${negativeMitigants.map(mitigant => `
              <div style="background: #f0fdf4; border: 1px solid #bbf7d0; padding: 0.75rem; border-radius: 8px; display: flex; justify-content: space-between; align-items: flex-start; gap: 0.75rem;">
                <div>
                  <strong style="color: #166534; font-size: 0.88rem; display: block;">✓ ${mitigant.title}</strong>
                  <span style="color: #475569; font-size: 0.8rem; margin-top: 0.15rem; display: block;">${mitigant.description}</span>
                </div>
                <span style="background: #059669; color: #ffffff; font-weight: 800; font-size: 0.78rem; padding: 0.2rem 0.6rem; border-radius: 20px; white-space: nowrap;">
                  ${mitigant.weight}
                </span>
              </div>
            `).join('')}
          </div>
        ` : `
          <div style="font-size: 0.82rem; color: #64748b; font-style: italic; background: #f8fafc; padding: 0.6rem; border-radius: 6px;">
            No trust mitigants applied for this transaction.
          </div>
        `}
      </div>
    </div>
  `;
}
