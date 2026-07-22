/**
 * FINSPARK - Account Takeover (ATO) Threat Intelligence UI Controller
 * Fetches real database telemetry, renders ATO risk score, weighted risk signals, device/IP analysis, impossible travel anomalies, and analyst actions.
 */

let currentQuery = '';
let currentTargetUserId = '';
let autoRefreshTimer = null;

document.addEventListener('DOMContentLoaded', () => {
  initATOPortal();
});

async function initATOPortal() {
  // 1. Session Verification
  try {
    const authRes = await fetch('/api/analyst/me');
    const authData = await authRes.json();

    if (!authRes.ok || !authData.authenticated) {
      window.location.href = 'analyst-login.html';
      return;
    }

    const infoEl = document.getElementById('analyst-info');
    if (infoEl && authData.analyst) {
      infoEl.textContent = `Analyst: ${authData.analyst.email} (${authData.analyst.role || 'Investigator'})`;
    }

  } catch (err) {
    window.location.href = 'analyst-login.html';
    return;
  }

  // Logout Button
  const logoutBtn = document.getElementById('analyst-logout-btn');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', async () => {
      if (autoRefreshTimer) clearInterval(autoRefreshTimer);
      try { await fetch('/api/analyst/logout', { method: 'POST' }); } catch (err) {}
      window.location.href = 'analyst-login.html';
    });
  }

  // ATO Search Form
  const form = document.getElementById('ato-search-form');
  const queryInput = document.getElementById('ato-query-input');
  const alertEl = document.getElementById('ato-alert');

  if (form) {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (alertEl) alertEl.style.display = 'none';

      const q = queryInput.value.trim();
      if (!q) return;

      currentQuery = q;
      const submitBtn = document.getElementById('ato-search-btn');
      submitBtn.disabled = true;
      submitBtn.textContent = 'Running Intelligence...';

      await loadATOIntelligence(currentQuery, true);
      submitBtn.disabled = false;
      submitBtn.textContent = 'Run ATO Intelligence';
    });
  }

  // Periodic 6s silent refresh
  autoRefreshTimer = setInterval(async () => {
    if (currentQuery) {
      await loadATOIntelligence(currentQuery, false);
    }
  }, 6000);
}

/**
 * Loads ATO Threat Intelligence Data from backend API
 */
async function loadATOIntelligence(query, isManualSearch = false) {
  const alertEl = document.getElementById('ato-alert');
  try {
    const res = await fetch(`/api/analyst/ato?accountNumber=${encodeURIComponent(query)}`);
    const data = await res.json();

    if (!res.ok || !data.found) {
      if (isManualSearch) {
        document.getElementById('ato-workspace').style.display = 'none';
        if (alertEl) {
          alertEl.textContent = data.message || `No database record found for account '${query}'.`;
          alertEl.style.display = 'block';
        }
      }
      return;
    }

    currentTargetUserId = data.identity.user_id;
    renderATODashboard(data);

    const workspace = document.getElementById('ato-workspace');
    if (workspace) workspace.style.display = 'block';

    if (isManualSearch && workspace) {
      window.scrollTo({ top: workspace.offsetTop - 80, behavior: 'smooth' });
    }

  } catch (err) {
    if (isManualSearch && alertEl) {
      alertEl.textContent = 'Network error fetching Account Takeover threat intelligence.';
      alertEl.style.display = 'block';
    }
  }
}

/**
 * Renders ATO Intelligence Dashboard
 */
function renderATODashboard(data) {
  const risk = data.current_risk;
  const ll = data.latest_login;
  const act = data.recent_activity;
  const dev = data.device_analysis;
  const ipLoc = data.ip_location_analysis;
  const beh = data.behavior_summary;

  // 1. Current Risk Status
  document.getElementById('ato-score-val').textContent = `${risk.ato_score}/100`;
  document.getElementById('ato-level-val').textContent = risk.risk_level;
  document.getElementById('ato-status-val').textContent = risk.status;
  document.getElementById('ato-updated-val').textContent = new Date(risk.last_updated).toLocaleTimeString();

  const riskBadge = document.getElementById('ato-risk-badge');
  if (riskBadge) {
    riskBadge.textContent = `${risk.risk_level} RISK (${risk.ato_score}/100)`;
    riskBadge.className = risk.risk_level === 'CRITICAL' ? 'badge badge-critical' : (risk.risk_level === 'HIGH' ? 'badge badge-high' : (risk.risk_level === 'MEDIUM' ? 'badge badge-medium' : 'badge badge-low'));
  }

  // 2. Latest Login
  document.getElementById('ll-time').textContent = new Date(ll.login_time).toLocaleString();
  document.getElementById('ll-ip').textContent = ll.ip_address;
  document.getElementById('ll-loc').textContent = ll.location;
  document.getElementById('ll-dev').textContent = ll.device_type;
  document.getElementById('ll-browser').textContent = `${ll.browser} (${ll.operating_system})`;

  // 3. Recent Activity & Behavior
  document.getElementById('act-sessions').textContent = act.successful_logins;
  document.getElementById('act-failed').textContent = act.failed_logins;
  document.getElementById('act-pwd').textContent = act.password_changes;
  document.getElementById('beh-dev-ratio').textContent = `${beh.deviation_ratio}x`;

  // 4. ATO Risk Signals Engine
  const signalsContainer = document.getElementById('signals-container');
  if (signalsContainer) {
    const signals = data.risk_signals || [];
    signalsContainer.innerHTML = signals.map(s => {
      const badgeClass = s.severity === 'CRITICAL' ? 'badge-critical' : (s.severity === 'HIGH' ? 'badge-high' : (s.severity === 'MEDIUM' ? 'badge-medium' : 'badge-low'));
      return `
        <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-left: 4px solid ${s.severity === 'CRITICAL' || s.severity === 'HIGH' ? '#dc2626' : '#2563eb'}; padding: 0.85rem; border-radius: 6px; margin-bottom: 0.75rem;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.35rem;">
            <strong style="font-size: 0.95rem; color: #0f172a;">${s.signal_name} (${s.weight >= 0 ? '+' : ''}${s.weight} Weight)</strong>
            <span class="badge ${badgeClass}">${s.severity} SEVERITY</span>
          </div>
          <div style="font-size: 0.85rem; color: #475569;">${s.evidence}</div>
          <div style="font-size: 0.75rem; color: #94a3b8; margin-top: 0.25rem;">Timestamp: ${new Date(s.timestamp).toLocaleString()}</div>
        </div>
      `;
    }).join('');
  }

  // 5. Device & IP Analysis
  document.getElementById('dev-count').textContent = dev.total_known_devices_count;
  
  const devNewEl = document.getElementById('dev-new-flag');
  if (devNewEl) {
    devNewEl.textContent = dev.is_new_device ? 'YES (NEW DEVICE DETECTED)' : 'NO (KNOWN DEVICE)';
    devNewEl.style.color = dev.is_new_device ? '#dc2626' : '#059669';
  }

  const devReuseEl = document.getElementById('dev-reuse-flag');
  if (devReuseEl) {
    devReuseEl.textContent = dev.device_reuse_detected ? `DETECTED (${dev.colliding_accounts_count} ACCOUNTS)` : 'NONE (EXCLUSIVE)';
    devReuseEl.style.color = dev.device_reuse_detected ? '#dc2626' : '#059669';
  }

  const travelEl = document.getElementById('travel-flag');
  if (travelEl) {
    travelEl.textContent = ipLoc.impossible_travel_detected ? 'ANOMALY DETECTED (HIGH SPEED)' : 'NORMAL MOVEMENT';
    travelEl.style.color = ipLoc.impossible_travel_detected ? '#dc2626' : '#059669';
  }

  const travelEvidenceEl = document.getElementById('travel-evidence-text');
  if (travelEvidenceEl) {
    travelEvidenceEl.textContent = ipLoc.travel_evidence;
  }

  // 6. Chronological Login Timeline
  const timelineBody = document.getElementById('timeline-table-body');
  if (timelineBody) {
    const timeline = data.login_timeline || [];
    if (timeline.length === 0) {
      timelineBody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:#64748b;">No timeline entries available</td></tr>`;
    } else {
      timelineBody.innerHTML = timeline.map(t => {
        return `
          <tr>
            <td><strong>${new Date(t.timestamp).toLocaleString()}</strong></td>
            <td><span class="badge ${t.event_type.includes('Transaction') ? 'badge-medium' : 'badge-low'}">${t.event_type}</span></td>
            <td style="font-size:0.85rem;">${t.description}</td>
            <td style="color:#2563eb;">${t.ip_address}</td>
            <td>${t.location}</td>
            <td><span class="badge ${t.risk_score >= 50 ? 'badge-high' : 'badge-low'}">${t.risk_score}</span></td>
          </tr>
        `;
      }).join('');
    }
  }
}

/**
 * Executes Analyst Remediation Actions (Mark Safe, Lock Account, etc.)
 */
window.executeAnalystAction = async function(actionType) {
  if (!currentTargetUserId) return;
  const statusMsg = document.getElementById('action-status-msg');
  
  try {
    const res = await fetch('/api/analyst/action', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        targetUserId: currentTargetUserId,
        action: actionType,
        notes: `Executed ${actionType} remediation from ATO Threat Console.`
      })
    });

    const data = await res.json();
    if (statusMsg) {
      statusMsg.style.display = 'block';
      if (res.ok && data.success) {
        statusMsg.style.color = '#059669';
        statusMsg.textContent = `✅ Action '${actionType}' successfully executed and recorded in database audit trail.`;
      } else {
        statusMsg.style.color = '#dc2626';
        statusMsg.textContent = `❌ Action failed: ${data.message || 'Error recording action'}`;
      }
    }

  } catch (err) {
    if (statusMsg) {
      statusMsg.style.display = 'block';
      statusMsg.style.color = '#dc2626';
      statusMsg.textContent = 'Network error executing analyst action.';
    }
  }
};
