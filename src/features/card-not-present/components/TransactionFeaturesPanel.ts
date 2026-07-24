/**
 * Transaction Features Panel Component
 * Displays behavioral transaction attributes used by the AI Risk Engine
 */

import { CNPTransaction } from '../types/cnpTypes.js';

export function renderTransactionFeaturesPanel(transaction: CNPTransaction): string {
  const isHighAmount = transaction.previousAverageAmount > 0 && (transaction.amount / transaction.previousAverageAmount >= 2.5);
  const isHighVelocity = transaction.velocityLastMinute >= 3 || transaction.velocityLastHour >= 8;

  return `
    <div class="account-card" style="margin-bottom: 1.5rem; border-top: 4px solid #0284c7; border-radius: 12px;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; border-bottom: 1px solid #f1f5f9; padding-bottom: 0.75rem;">
        <div>
          <h3 style="margin: 0; font-size: 1.1rem; color: #0f172a; display: flex; align-items: center; gap: 0.5rem;">
            <span>📊</span> Behavioral Transaction Features
          </h3>
          <p style="margin: 0.2rem 0 0 0; color: #64748b; font-size: 0.8rem;">Historical pattern and payment velocity metrics</p>
        </div>
        <span class="badge" style="background: #e0f2fe; color: #0369a1; font-size: 0.75rem;">Behavior Engine</span>
      </div>

      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 0.85rem;">
        <!-- Amount vs Historical Avg -->
        <div style="background: ${isHighAmount ? '#fff7ed' : '#f8fafc'}; border: 1px solid ${isHighAmount ? '#fed7aa' : '#e2e8f0'}; padding: 0.75rem; border-radius: 8px;">
          <div style="font-size: 0.75rem; color: #64748b; font-weight: 600;">Payment Amount</div>
          <div style="font-size: 0.95rem; font-weight: 700; color: ${isHighAmount ? '#c2410c' : '#0f172a'}; margin-top: 0.15rem;">
            ₹${transaction.amount.toLocaleString()} ${isHighAmount ? '⚠️ Outlier' : ''}
          </div>
          <div style="font-size: 0.72rem; color: #475569; margin-top: 0.2rem;">User Avg: ₹${transaction.previousAverageAmount.toLocaleString()}</div>
        </div>

        <!-- Velocity -->
        <div style="background: ${isHighVelocity ? '#fef2f2' : '#f8fafc'}; border: 1px solid ${isHighVelocity ? '#fecaca' : '#e2e8f0'}; padding: 0.75rem; border-radius: 8px;">
          <div style="font-size: 0.75rem; color: #64748b; font-weight: 600;">Payment Velocity</div>
          <div style="font-size: 0.95rem; font-weight: 700; color: ${isHighVelocity ? '#dc2626' : '#0f172a'}; margin-top: 0.15rem;">
            ⚡ ${transaction.velocityLastMinute} / min | ${transaction.velocityLastHour} / hr
          </div>
          <div style="font-size: 0.72rem; color: #475569; margin-top: 0.2rem;">Frequency status: ${isHighVelocity ? 'High Burst' : 'Normal'}</div>
        </div>

        <!-- Merchant History -->
        <div style="background: #f8fafc; border: 1px solid #e2e8f0; padding: 0.75rem; border-radius: 8px;">
          <div style="font-size: 0.75rem; color: #64748b; font-weight: 600;">Merchant Relationship</div>
          <div style="font-size: 0.95rem; font-weight: 700; color: #0f172a; margin-top: 0.15rem;">
            ${transaction.isNewMerchant ? '🆕 New Merchant' : '🏢 Existing Merchant'}
          </div>
          <div style="font-size: 0.72rem; color: #475569; margin-top: 0.2rem;">Category: ${transaction.merchantCategory}</div>
        </div>

        <!-- Beneficiary & Card -->
        <div style="background: #f8fafc; border: 1px solid #e2e8f0; padding: 0.75rem; border-radius: 8px;">
          <div style="font-size: 0.75rem; color: #64748b; font-weight: 600;">Card & Beneficiary History</div>
          <div style="font-size: 0.95rem; font-weight: 700; color: #0f172a; margin-top: 0.15rem;">
            ${transaction.isNewCard ? '💳 New Card' : '💳 Saved Card'}
          </div>
          <div style="font-size: 0.72rem; color: #475569; margin-top: 0.2rem;">History: ${transaction.beneficiaryHistory}</div>
        </div>

        <!-- International & Currency -->
        <div style="background: ${transaction.isInternational ? '#fff7ed' : '#f8fafc'}; border: 1px solid ${transaction.isInternational ? '#fed7aa' : '#e2e8f0'}; padding: 0.75rem; border-radius: 8px;">
          <div style="font-size: 0.75rem; color: #64748b; font-weight: 600;">Cross-Border & Currency</div>
          <div style="font-size: 0.95rem; font-weight: 700; color: ${transaction.isInternational ? '#c2410c' : '#0f172a'}; margin-top: 0.15rem;">
            ${transaction.isInternational ? '🌍 International (' + transaction.currency + ')' : '🏠 Domestic (' + transaction.currency + ')'}
          </div>
          <div style="font-size: 0.72rem; color: #475569; margin-top: 0.2rem;">Timestamp: ${new Date(transaction.paymentTimestamp).toLocaleTimeString()}</div>
        </div>
      </div>
    </div>
  `;
}
