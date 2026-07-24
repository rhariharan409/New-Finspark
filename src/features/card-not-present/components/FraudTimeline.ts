/**
 * Fraud Timeline Component
 * Live updating vertical timeline visualizing payment progression & security checks
 */

import { TimelineEvent } from '../types/cnpTypes.js';

export function renderFraudTimeline(events: TimelineEvent[]): string {
  const getSeverityStyle = (severity: string) => {
    switch (severity) {
      case 'CRITICAL':
        return { bg: '#fef2f2', border: '#fecaca', text: '#dc2626', badge: 'bg-red-100 text-red-800' };
      case 'HIGH':
        return { bg: '#fff7ed', border: '#fed7aa', text: '#ea580c', badge: 'bg-orange-100 text-orange-800' };
      case 'MEDIUM':
        return { bg: '#fffbeb', border: '#fde68a', text: '#d97706', badge: 'bg-amber-100 text-amber-800' };
      default:
        return { bg: '#f0fdf4', border: '#bbf7d0', text: '#059669', badge: 'bg-emerald-100 text-emerald-800' };
    }
  };

  return `
    <div class="account-card" style="margin-bottom: 1.5rem; border-top: 4px solid #7c3aed; border-radius: 12px;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.25rem; border-bottom: 1px solid #f1f5f9; padding-bottom: 0.75rem;">
        <div>
          <h3 style="margin: 0; font-size: 1.15rem; color: #0f172a; display: flex; align-items: center; gap: 0.5rem;">
            <span>⏱️</span> Live CNP Fraud Event Timeline
          </h3>
          <p style="margin: 0.2rem 0 0 0; color: #64748b; font-size: 0.82rem;">Sequential audit trace of customer login, telemetry signals, payment input, and AI risk decision</p>
        </div>
        <span class="badge" style="background: #f3e8ff; color: #7e22ce; border: 1px solid #d8b4fe; font-size: 0.75rem;">Real-time Telemetry Trace</span>
      </div>

      <div class="cnp-timeline" style="position: relative; padding-left: 2rem; margin-left: 0.5rem; border-left: 3px solid #cbd5e1;">
        ${events.map((evt, index) => {
          const style = getSeverityStyle(evt.severity);
          const isLast = index === events.length - 1;

          return `
            <div 
              class="cnp-timeline-item" 
              style="
                position: relative; 
                margin-bottom: ${isLast ? '0' : '1.25rem'}; 
                animation: fadeIn 0.4s ease-in-out ${index * 0.1}s both;
              "
            >
              <!-- Icon Node Dot -->
              <div 
                style="
                  position: absolute; 
                  left: -2.75rem; 
                  top: 0; 
                  width: 32px; 
                  height: 32px; 
                  border-radius: 50%; 
                  background: ${style.bg}; 
                  border: 2px solid ${style.border}; 
                  display: flex; 
                  align-items: center; 
                  justify-content: center; 
                  font-size: 1rem;
                  box-shadow: 0 2px 4px rgba(0,0,0,0.05);
                "
              >
                ${evt.icon}
              </div>

              <!-- Content Box -->
              <div 
                style="
                  background: ${style.bg}; 
                  border: 1px solid ${style.border}; 
                  padding: 0.85rem 1rem; 
                  border-radius: 8px;
                "
              >
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.25rem; flex-wrap: wrap; gap: 0.5rem;">
                  <strong style="color: #0f172a; font-size: 0.92rem;">${evt.title}</strong>
                  <div style="display: flex; align-items: center; gap: 0.5rem;">
                    <span style="font-family: monospace; font-size: 0.78rem; color: #64748b; font-weight: 600;">${evt.timestamp}</span>
                    <span style="background: ${style.border}; color: ${style.text}; font-size: 0.68rem; font-weight: 700; padding: 0.15rem 0.45rem; border-radius: 4px; text-transform: uppercase;">
                      ${evt.severity}
                    </span>
                  </div>
                </div>

                <div style="font-size: 0.82rem; color: #334155; line-height: 1.4;">
                  ${evt.description}
                </div>
              </div>
            </div>
          `;
        }).join('')}
      </div>
    </div>
  `;
}
