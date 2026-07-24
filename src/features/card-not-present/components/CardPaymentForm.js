/**
 * Card Payment Form Component (JS Runtime)
 */

import { MERCHANT_CATEGORIES } from '../constants.js';

export function renderCardPaymentForm(transaction) {
  return `
    <div class="account-card" style="margin-bottom: 1.5rem; border-top: 4px solid #2563eb; border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05);">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; border-bottom: 1px solid #f1f5f9; padding-bottom: 0.75rem;">
        <div>
          <h3 style="margin: 0; font-size: 1.15rem; color: #0f172a; display: flex; align-items: center; gap: 0.5rem;">
            <span>💳</span> Card Payment Simulation
          </h3>
          <p style="margin: 0.2rem 0 0 0; color: #64748b; font-size: 0.82rem;">Enter card details to simulate Card Not Present (CNP) payment authorization</p>
        </div>
        <span class="badge" style="background: #eff6ff; color: #1d4ed8; border: 1px solid #bfdbfe; font-size: 0.75rem;">CNP Payment Flow</span>
      </div>

      <form id="cnp-payment-form">
        <!-- Card Number & Holder Row -->
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; margin-bottom: 1rem;">
          <div class="form-group" style="margin: 0;">
            <label class="form-label" for="cnp-card-number" style="font-weight: 600; font-size: 0.85rem;">Card Number</label>
            <input type="text" id="cnp-card-number" class="form-input" value="${transaction.cardNumber}" placeholder="4532 •••• •••• 8912" required>
          </div>

          <div class="form-group" style="margin: 0;">
            <label class="form-label" for="cnp-cardholder-name" style="font-weight: 600; font-size: 0.85rem;">Cardholder Name</label>
            <input type="text" id="cnp-cardholder-name" class="form-input" value="${transaction.cardholderName}" placeholder="Rahul Sharma" required>
          </div>
        </div>

        <!-- Expiry, CVV & Currency Row -->
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 1rem; margin-bottom: 1rem;">
          <div class="form-group" style="margin: 0;">
            <label class="form-label" for="cnp-expiry" style="font-weight: 600; font-size: 0.85rem;">Expiry Date</label>
            <input type="text" id="cnp-expiry" class="form-input" value="${transaction.expiryDate}" placeholder="MM/YY" required>
          </div>

          <div class="form-group" style="margin: 0;">
            <label class="form-label" for="cnp-cvv" style="font-weight: 600; font-size: 0.85rem;">CVV</label>
            <input type="password" id="cnp-cvv" class="form-input" value="${transaction.cvv}" maxlength="4" placeholder="•••" required>
          </div>

          <div class="form-group" style="margin: 0;">
            <label class="form-label" for="cnp-currency" style="font-weight: 600; font-size: 0.85rem;">Currency</label>
            <select id="cnp-currency" class="form-input">
              <option value="INR (₹)" ${transaction.currency.includes('INR') ? 'selected' : ''}>INR (₹)</option>
              <option value="USD ($)" ${transaction.currency.includes('USD') ? 'selected' : ''}>USD ($)</option>
              <option value="EUR (€)" ${transaction.currency.includes('EUR') ? 'selected' : ''}>EUR (€)</option>
            </select>
          </div>

          <div class="form-group" style="margin: 0;">
            <label class="form-label" for="cnp-amount" style="font-weight: 600; font-size: 0.85rem;">Amount</label>
            <input type="number" id="cnp-amount" class="form-input" value="${transaction.amount}" step="0.01" min="1" required>
          </div>
        </div>

        <!-- Merchant Name & Category Row -->
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; margin-bottom: 1.25rem;">
          <div class="form-group" style="margin: 0;">
            <label class="form-label" for="cnp-merchant-name" style="font-weight: 600; font-size: 0.85rem;">Merchant Name</label>
            <input type="text" id="cnp-merchant-name" class="form-input" value="${transaction.merchantName}" placeholder="Flipkart Online Retail" required>
          </div>

          <div class="form-group" style="margin: 0;">
            <label class="form-label" for="cnp-merchant-category" style="font-weight: 600; font-size: 0.85rem;">Merchant Category</label>
            <select id="cnp-merchant-category" class="form-input">
              ${MERCHANT_CATEGORIES.map(cat => `
                <option value="${cat}" ${transaction.merchantCategory === cat ? 'selected' : ''}>${cat}</option>
              `).join('')}
            </select>
          </div>
        </div>

        <button type="submit" id="cnp-submit-btn" class="btn btn-primary btn-full" style="padding: 0.85rem; font-size: 1rem; font-weight: 700; display: flex; justify-content: center; align-items: center; gap: 0.5rem; border-radius: 8px;">
          <span>⚡</span> Run AI Fraud Risk Engine & Simulate Payment
        </button>
      </form>
    </div>
  `;
}
