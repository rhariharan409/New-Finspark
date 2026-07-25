/**
 * Simulation Mode Selector Component
 * Interactive scenario switcher for hackathon live demo (Light Theme)
 */

import { SIMULATION_SCENARIOS } from '../mock/scenarios.js';

export function renderSimulationModeSelector(
  activeScenarioId: string,
  onSelectScenario?: (scenarioId: string) => void
): string {
  return `
    <div class="cnp-scenario-bar" style="background: #ffffff; padding: 1.25rem; border-radius: 12px; margin-bottom: 1.5rem; border: 1px solid #e2e8f0; border-top: 4px solid #005994; box-shadow: 0 4px 12px rgba(0, 89, 148, 0.05);">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.85rem; flex-wrap: wrap; gap: 0.5rem;">
        <div>
          <span style="background: #e0f2fe; color: #0284c7; border: 1px solid #bae6fd; padding: 0.2rem 0.6rem; border-radius: 20px; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px;">
            🎮 HACKATHON DEMO MODES
          </span>
          <h3 style="color: #0f172a; margin: 0.35rem 0 0 0; font-size: 1.1rem; font-weight: 700;">
            Select Fraud Simulation Scenario
          </h3>
        </div>
        <div style="color: #64748b; font-size: 0.8rem; font-weight: 500;">
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
                background: ${isActive ? '#ffffff' : '#f8fafc'};
                border: ${isActive ? `2px solid ${sc.badgeColor}` : '1px solid #cbd5e1'};
                box-shadow: ${isActive ? `0 4px 14px ${sc.badgeColor}25, 0 1px 3px rgba(0,0,0,0.05)` : 'none'};
                color: #0f172a;
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
                  <strong style="font-size: 0.85rem; color: #0f172a; font-weight: 700;">${sc.name}</strong>
                </div>
                <div style="font-size: 0.75rem; color: #64748b; line-height: 1.2; margin-bottom: 0.5rem; font-weight: 500;">${sc.subtitle}</div>
              </div>
              <span style="background: ${sc.badgeColor}15; color: ${sc.badgeColor}; border: 1px solid ${sc.badgeColor}40; font-size: 0.68rem; font-weight: 700; padding: 0.15rem 0.4rem; border-radius: 4px; display: inline-block; width: fit-content;">
                ${sc.badge}
              </span>
            </button>
          `;
        }).join('')}
      </div>
    </div>
  `;
}
