/**
 * Simulation Mode Selector Component (JS Runtime)
 */

import { SIMULATION_SCENARIOS } from '../mock/scenarios.js';

export function renderSimulationModeSelector(activeScenarioId) {
  return `
    <div class="cnp-scenario-bar" style="background: #0f172a; padding: 1.25rem; border-radius: 12px; margin-bottom: 1.5rem; border: 1px solid #1e293b; box-shadow: 0 4px 12px rgba(0,0,0,0.15);">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.85rem; flex-wrap: wrap; gap: 0.5rem;">
        <div>
          <span style="background: #38bdf820; color: #38bdf8; border: 1px solid #38bdf840; padding: 0.2rem 0.6rem; border-radius: 20px; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px;">
            🎮 HACKATHON DEMO MODES
          </span>
          <h3 style="color: #ffffff; margin: 0.35rem 0 0 0; font-size: 1.1rem; font-weight: 700;">
            Select Fraud Simulation Scenario
          </h3>
        </div>
        <div style="color: #94a3b8; font-size: 0.8rem;">
          Click any preset scenario to auto-populate cybersecurity telemetry & transaction signals
        </div>
      </div>

      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 0.75rem;">
        ${SIMULATION_SCENARIOS.map(sc => {
          const isActive = sc.id === activeScenarioId;
          return `
            <button 
              type="button"
              class="cnp-scenario-btn ${isActive ? 'active' : ''}"
              data-scenario-id="${sc.id}"
              style="
                background: ${isActive ? '#1e293b' : '#0f172a'};
                border: 2px solid ${isActive ? sc.badgeColor : '#334155'};
                color: #ffffff;
                padding: 0.75rem;
                border-radius: 8px;
                cursor: pointer;
                text-align: left;
                transition: all 0.2s ease;
                display: flex;
                flex-direction: column;
                justify-content: space-between;
              "
            >
              <div>
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.25rem;">
                  <strong style="font-size: 0.85rem; color: ${isActive ? '#ffffff' : '#e2e8f0'};">${sc.name}</strong>
                </div>
                <div style="font-size: 0.75rem; color: #94a3b8; line-height: 1.2; margin-bottom: 0.5rem;">${sc.subtitle}</div>
              </div>
              <span style="background: ${sc.badgeColor}20; color: ${sc.badgeColor}; border: 1px solid ${sc.badgeColor}40; font-size: 0.68rem; font-weight: 700; padding: 0.15rem 0.4rem; border-radius: 4px; display: inline-block; width: fit-content;">
                ${sc.badge}
              </span>
            </button>
          `;
        }).join('')}
      </div>
    </div>
  `;
}
