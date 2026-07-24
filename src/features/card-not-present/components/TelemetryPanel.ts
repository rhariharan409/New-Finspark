/**
 * Telemetry Panel Component
 * Displays grid of cybersecurity telemetry signals automatically captured by system
 */

import { CNPTelemetry } from '../types/cnpTypes.js';

export function renderTelemetryPanel(telemetry: CNPTelemetry): string {
  const isUnknownDevice = telemetry.deviceStatus === 'Unknown Device';
  const isVpn = telemetry.vpnDetected;
  const isProxy = telemetry.proxyDetected;
  const isTravel = telemetry.impossibleTravel;
  const isRooted = telemetry.rootedJailbroken;
  const isPublicWifi = telemetry.wifiCategory === 'Public WiFi';

  return `
    <div class="account-card" style="margin-bottom: 1.5rem; border-top: 4px solid #0f172a; border-radius: 12px;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; border-bottom: 1px solid #f1f5f9; padding-bottom: 0.75rem;">
        <div>
          <h3 style="margin: 0; font-size: 1.1rem; color: #0f172a; display: flex; align-items: center; gap: 0.5rem;">
            <span>🛡️</span> Cybersecurity Telemetry Signals
          </h3>
          <p style="margin: 0.2rem 0 0 0; color: #64748b; font-size: 0.8rem;">Automated security diagnostics captured at time of payment</p>
        </div>
        <span class="badge" style="background: #0f172a; color: #ffffff; font-size: 0.75rem;">Live Signals</span>
      </div>

      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 0.85rem;">
        <!-- Device Status -->
        <div style="background: ${isUnknownDevice ? '#fef2f2' : '#f0fdf4'}; border: 1px solid ${isUnknownDevice ? '#fecaca' : '#bbf7d0'}; padding: 0.75rem; border-radius: 8px;">
          <div style="font-size: 0.75rem; color: #64748b; font-weight: 600;">Device Status</div>
          <div style="font-size: 0.95rem; font-weight: 700; color: ${isUnknownDevice ? '#dc2626' : '#15803d'}; margin-top: 0.15rem;">
            ${isUnknownDevice ? '⚠️ Unknown Device' : '✅ Known Device'}
          </div>
          <div style="font-size: 0.72rem; color: #475569; margin-top: 0.2rem;">${telemetry.browser} on ${telemetry.os}</div>
        </div>

        <!-- Impossible Travel -->
        <div style="background: ${isTravel ? '#fef2f2' : '#f8fafc'}; border: 1px solid ${isTravel ? '#fecaca' : '#e2e8f0'}; padding: 0.75rem; border-radius: 8px;">
          <div style="font-size: 0.75rem; color: #64748b; font-weight: 600;">Location Velocity</div>
          <div style="font-size: 0.95rem; font-weight: 700; color: ${isTravel ? '#dc2626' : '#0f172a'}; margin-top: 0.15rem;">
            ${isTravel ? '🚨 Impossible Travel' : '📍 ' + telemetry.currentCity}
          </div>
          <div style="font-size: 0.72rem; color: #475569; margin-top: 0.2rem;">Prev: ${telemetry.previousCity}</div>
        </div>

        <!-- VPN / Proxy -->
        <div style="background: ${isVpn || isProxy ? '#fff7ed' : '#f8fafc'}; border: 1px solid ${isVpn || isProxy ? '#fed7aa' : '#e2e8f0'}; padding: 0.75rem; border-radius: 8px;">
          <div style="font-size: 0.75rem; color: #64748b; font-weight: 600;">VPN / Proxy Tunneling</div>
          <div style="font-size: 0.95rem; font-weight: 700; color: ${isVpn || isProxy ? '#c2410c' : '#0f172a'}; margin-top: 0.15rem;">
            ${isVpn ? '🛡️ VPN Active' : isProxy ? '🔄 Proxy Active' : '✅ No Anonymizer'}
          </div>
          <div style="font-size: 0.72rem; color: #475569; margin-top: 0.2rem;">IP: ${telemetry.ipAddress}</div>
        </div>

        <!-- Rooted / Jailbroken -->
        <div style="background: ${isRooted ? '#fef2f2' : '#f8fafc'}; border: 1px solid ${isRooted ? '#fecaca' : '#e2e8f0'}; padding: 0.75rem; border-radius: 8px;">
          <div style="font-size: 0.75rem; color: #64748b; font-weight: 600;">OS Integrity</div>
          <div style="font-size: 0.95rem; font-weight: 700; color: ${isRooted ? '#dc2626' : '#0f172a'}; margin-top: 0.15rem;">
            ${isRooted ? '🔓 Rooted / Jailbroken' : '🔒 Secure Sandbox'}
          </div>
          <div style="font-size: 0.72rem; color: #475569; margin-top: 0.2rem;">Biometric: ${telemetry.biometricUsed ? 'Passed ✅' : 'None'}</div>
        </div>

        <!-- Network Category -->
        <div style="background: ${isPublicWifi ? '#fffbeb' : '#f8fafc'}; border: 1px solid ${isPublicWifi ? '#fde68a' : '#e2e8f0'}; padding: 0.75rem; border-radius: 8px;">
          <div style="font-size: 0.75rem; color: #64748b; font-weight: 600;">Network Security</div>
          <div style="font-size: 0.95rem; font-weight: 700; color: ${isPublicWifi ? '#b45309' : '#0f172a'}; margin-top: 0.15rem;">
            📡 ${telemetry.wifiCategory}
          </div>
          <div style="font-size: 0.72rem; color: #475569; margin-top: 0.2rem;">Type: ${telemetry.networkType}</div>
        </div>

        <!-- Failed Login / OTP Attempts -->
        <div style="background: ${telemetry.failedLoginAttempts > 0 || telemetry.otpAttempts > 1 ? '#fff7ed' : '#f8fafc'}; border: 1px solid ${telemetry.failedLoginAttempts > 0 ? '#fed7aa' : '#e2e8f0'}; padding: 0.75rem; border-radius: 8px;">
          <div style="font-size: 0.75rem; color: #64748b; font-weight: 600;">Authentication Attempts</div>
          <div style="font-size: 0.95rem; font-weight: 700; color: #0f172a; margin-top: 0.15rem;">
            🔑 OTP: ${telemetry.otpAttempts} | Failed: ${telemetry.failedLoginAttempts}
          </div>
          <div style="font-size: 0.72rem; color: #475569; margin-top: 0.2rem;">Login Time: ${telemetry.loginTime}</div>
        </div>
      </div>
    </div>
  `;
}
