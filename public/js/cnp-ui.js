/**
 * CNP UI Client Script
 * Powers interactive Card Not Present Fraud Detection demo interface
 */

import { cnpService } from '../src/features/card-not-present/services/cnpService.js';
import { renderCNPDashboard } from '../src/features/card-not-present/components/CNPDashboard.js';
import { SIMULATION_SCENARIOS } from '../src/features/card-not-present/mock/scenarios.js';

let currentScenarioId = 'SCENARIO-1';
let currentScenario = SIMULATION_SCENARIOS[0];

let activeSimulation = cnpService.runSimulation(
  currentScenario.transaction,
  currentScenario.telemetry
);

function render() {
  const root = document.getElementById('cnp-app-root');
  if (!root) return;

  root.innerHTML = renderCNPDashboard(activeSimulation, currentScenarioId);
  attachEventListeners();
}

function attachEventListeners() {
  // Scenario selector buttons
  const scenarioBtns = document.querySelectorAll('.cnp-scenario-btn');
  scenarioBtns.forEach(btn => {
    btn.addEventListener('click', (e) => {
      const scenarioId = btn.getAttribute('data-scenario-id');
      if (scenarioId) {
        switchScenario(scenarioId);
      }
    });
  });

  // Card Payment Form submission
  const form = document.getElementById('cnp-payment-form');
  if (form) {
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      handleFormSubmit();
    });
  }
}

function switchScenario(scenarioId) {
  currentScenarioId = scenarioId;
  currentScenario = SIMULATION_SCENARIOS.find(s => s.id === scenarioId) || SIMULATION_SCENARIOS[0];

  activeSimulation = cnpService.runSimulation(
    currentScenario.transaction,
    currentScenario.telemetry
  );

  render();
}

function handleFormSubmit() {
  const cardNumber = document.getElementById('cnp-card-number')?.value || '';
  const cardholderName = document.getElementById('cnp-cardholder-name')?.value || '';
  const expiryDate = document.getElementById('cnp-expiry')?.value || '';
  const cvv = document.getElementById('cnp-cvv')?.value || '';
  const currency = document.getElementById('cnp-currency')?.value || 'INR (₹)';
  const amount = parseFloat(document.getElementById('cnp-amount')?.value || '0');
  const merchantName = document.getElementById('cnp-merchant-name')?.value || '';
  const merchantCategory = document.getElementById('cnp-merchant-category')?.value || 'E-Commerce';

  // Merge updated form fields with scenario telemetry signals
  activeSimulation = cnpService.runSimulation(
    {
      ...currentScenario.transaction,
      cardNumber,
      cardholderName,
      expiryDate,
      cvv,
      currency,
      amount,
      merchantName,
      merchantCategory
    },
    currentScenario.telemetry
  );

  render();
}

// Initial render
document.addEventListener('DOMContentLoaded', () => {
  render();
});

// Fallback direct execution
render();
