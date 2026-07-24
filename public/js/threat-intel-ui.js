/**
 * FINSPARK - Unified Threat Intelligence Dashboard Controller
 * Single-context investigation controller that loads complete database context once and switches between 8 fraud engines (ATO, Money Mule, Credential Stuffing, Card Fraud, Synthetic Identity, API Abuse, Insider Threat, Device Intelligence) instantly.
 */

let currentQuery = '';
let intelContext = null; // Caches complete single-context investigation response
let activeModule = 'ato'; // Default tab
let autoRefreshTimer = null;

document.addEventListener('DOMContentLoaded', () => {
  initThreatIntelDashboard();
});

async function initThreatIntelDashboard() {
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

  // Check URL query parameters for pre-selected module or user search
  const urlParams = new URLSearchParams(window.location.search);
  const modParam = urlParams.get('module');
  if (modParam) {
    if (modParam === 'mule') activeModule = 'money_mule';
    else if (modParam === 'stuffing') activeModule = 'credential_stuffing';
    else if (modParam === 'card') activeModule = 'card_fraud';
    else if (modParam === 'synthetic') activeModule = 'synthetic_identity';
    else if (modParam === 'api') activeModule = 'api_abuse';
    else if (modParam === 'insider') activeModule = 'insider_threat';
    else if (modParam === 'device') activeModule = 'device_intelligence';
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

  // Search Form Listener
  const form = document.getElementById('intel-search-form');
  const queryInput = document.getElementById('intel-query-input');
  const alertEl = document.getElementById('intel-alert');

  if (form) {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (alertEl) alertEl.style.display = 'none';

      const q = queryInput.value.trim();
      if (!q) return;

      currentQuery = q;
      const submitBtn = document.getElementById('intel-search-btn');
      submitBtn.disabled = true;
      submitBtn.textContent = 'Loading Context...';

      await loadUnifiedInvestigationContext(currentQuery, true);
      submitBtn.disabled = false;
      submitBtn.textContent = 'Load Investigation Context';
    });
  }

  // Module Selector Tab Listeners
  const tabBtns = document.querySelectorAll('.module-tab-btn');
  tabBtns.forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      tabBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      activeModule = btn.getAttribute('data-module') || 'ato';

      if (intelContext) {
        renderModuleContent(activeModule, intelContext);
      }
    });
  });

  // Highlight initial active tab button
  tabBtns.forEach(btn => {
    if (btn.getAttribute('data-module') === activeModule) {
      tabBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
    }
  });

  // Session Filter Input Listener
  const sessionFilterInput = document.getElementById('session-filter-input');
  if (sessionFilterInput) {
    sessionFilterInput.addEventListener('input', () => {
      if (intelContext) renderSessionsTable(intelContext.sessions || [], sessionFilterInput.value);
    });
  }

  // Side Panel Close Button
  document.getElementById('sp-close-btn')?.addEventListener('click', closeSidePanel);

  // Periodic 6s silent refresh
  autoRefreshTimer = setInterval(async () => {
    if (currentQuery) {
      await loadUnifiedInvestigationContext(currentQuery, false);
    }
  }, 6000);
}

/**
 * Single-Context Loader: Fetches complete database investigation payload once
 */
async function loadUnifiedInvestigationContext(query, isManualSearch = false) {
  const alertEl = document.getElementById('intel-alert');
  try {
    const res = await fetch(`/api/analyst/threat-intel?query=${encodeURIComponent(query)}`);
    const data = await res.json();

    if (!res.ok || !data.found) {
      if (isManualSearch) {
        document.getElementById('intel-workspace').style.display = 'none';
        if (alertEl) {
          alertEl.textContent = data.message || `No database record found for search '${query}'.`;
          alertEl.style.display = 'block';
        }
      }
      return;
    }

    intelContext = data; // Cache context in memory

    renderSummaryCards(data.summary, data.identity);
    renderSessionsTable(data.sessions, '');
    renderModuleContent(activeModule, data);

    const workspace = document.getElementById('intel-workspace');
    if (workspace) workspace.style.display = 'block';

    if (isManualSearch && workspace) {
      window.scrollTo({ top: workspace.offsetTop - 80, behavior: 'smooth' });
    }

  } catch (err) {
    if (isManualSearch && alertEl) {
      alertEl.textContent = 'Network error fetching unified threat intelligence context.';
      alertEl.style.display = 'block';
    }
  }
}

/**
 * 1. Render Global Summary Cards
 */
function renderSummaryCards(sum, id) {
  document.getElementById('sum-total-sessions').textContent = sum.total_sessions || 0;
  document.getElementById('sum-allowed-sessions').textContent = sum.allowed_sessions || 0;
  document.getElementById('sum-stepup-sessions').textContent = sum.step_up_sessions || 0;
  document.getElementById('sum-blocked-sessions').textContent = sum.blocked_sessions || 0;
  document.getElementById('sum-failed-logins').textContent = sum.failed_login_attempts || 0;
  document.getElementById('sum-devices-ips').textContent = `${sum.unique_devices_count || 1} / ${sum.unique_ips_count || 1}`;
  document.getElementById('sum-money-sent').textContent = `₹${(sum.total_money_sent || 0).toFixed(2)}`;
  document.getElementById('sum-avg-risk').textContent = `${sum.average_risk_score}/100`;
  document.getElementById('sum-high-risk').textContent = `${sum.highest_risk_score}/100`;
  document.getElementById('sum-acc-status').textContent = (id.account_status || 'active').toUpperCase();

  const postureBadge = document.getElementById('overall-posture-badge');
  if (postureBadge) {
    const isHigh = sum.highest_risk_score >= 60;
    postureBadge.textContent = isHigh ? `HIGH THREAT LEVEL (${sum.highest_risk_score}/100)` : `NORMAL POSTURE (${sum.highest_risk_score}/100)`;
    postureBadge.className = isHigh ? 'badge badge-high' : 'badge badge-low';
  }
}

/**
 * 2. Render Session Overview Table
 */
function renderSessionsTable(sessions, filterText) {
  const body = document.getElementById('sessions-table-body');
  if (!body) return;

  let filtered = sessions || [];
  if (filterText && filterText.trim() !== '') {
    const f = filterText.toLowerCase().trim();
    filtered = filtered.filter(s =>
      s.session_id.toLowerCase().includes(f) ||
      s.ip_address.toLowerCase().includes(f) ||
      s.browser.toLowerCase().includes(f) ||
      s.decision.toLowerCase().includes(f)
    );
  }

  if (filtered.length === 0) {
    body.innerHTML = `<tr><td colspan="10" style="text-align:center; color:#64748b;">No matching sessions found</td></tr>`;
    return;
  }

  body.innerHTML = filtered.map(s => {
    const decClass = s.decision === 'BLOCK' ? 'badge-critical' : (s.decision === 'STEP-UP' ? 'badge-high' : (s.decision === 'MONITOR' ? 'badge-medium' : 'badge-low'));
    return `
      <tr>
        <td><strong>${s.session_id}</strong></td>
        <td>${new Date(s.login_time).toLocaleString()}</td>
        <td>${s.logout_time !== 'Active Session' ? new Date(s.logout_time).toLocaleString() : 'Active Session'}</td>
        <td>${s.duration_seconds > 0 ? `${s.duration_seconds}s` : 'Active'}</td>
        <td style="color:#2563eb;">${s.ip_address}</td>
        <td>${s.device} (${s.browser})</td>
        <td>${s.location}</td>
        <td><span class="badge ${s.risk_score >= 50 ? 'badge-high' : 'badge-low'}">${s.risk_score}/100</span></td>
        <td><span class="badge ${decClass}">${s.decision}</span></td>
        <td>
          <button type="button" class="btn btn-secondary" style="padding: 0.25rem 0.5rem; font-size: 0.75rem;" onclick="openSessionDrawer('${s.session_id}')">
            Inspect
          </button>
        </td>
      </tr>
    `;
  }).join('');
}

/**
 * 3. Dynamic Module Content Renderer (Switches views without reloading database)
 */
function renderModuleContent(modKey, data) {
  const container = document.getElementById('module-content-area');
  if (!container) return;

  const mods = data.modules || {};

  if (modKey === 'ato') {
    const ato = mods.ato || {};
    const risk = ato.current_risk || {};
    const signals = ato.risk_signals || [];

    container.innerHTML = `
      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1.25rem;">
        <div class="summary-box">
          <span style="font-size: 0.75rem; color: #64748b;">ATO Risk Score</span>
          <div style="font-size: 1.25rem; font-weight: 700; color: #dc2626;">${risk.ato_score || 0}/100</div>
        </div>
        <div class="summary-box">
          <span style="font-size: 0.75rem; color: #64748b;">ATO Threat Status</span>
          <div style="font-size: 1.25rem; font-weight: 700; color: #059669;">${risk.status || 'NORMAL'}</div>
        </div>
      </div>

      <h4 style="font-size: 0.95rem; color: #0f172a; margin-bottom: 0.75rem; border-bottom: 1px solid #e2e8f0; padding-bottom: 0.35rem;">Account Takeover Risk Signals</h4>
      ${signals.map(s => `
        <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-left: 4px solid #2563eb; padding: 0.85rem; border-radius: 6px; margin-bottom: 0.75rem;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.25rem;">
            <strong style="font-size: 0.9rem; color: #0f172a;">${s.signal_name} (${s.weight >= 0 ? '+' : ''}${s.weight} Weight)</strong>
            <span class="badge ${s.severity === 'CRITICAL' ? 'badge-critical' : 'badge-low'}">${s.severity} SEVERITY</span>
          </div>
          <div style="font-size: 0.85rem; color: #475569;">${s.evidence}</div>
        </div>
      `).join('')}
    `;

  } else if (modKey === 'money_mule') {
    const mule = mods.money_mule || {};
    container.innerHTML = `
      <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 1rem; margin-bottom: 1.25rem;">
        <div class="summary-box">
          <span style="font-size: 0.75rem; color: #64748b;">Connected Accounts</span>
          <div style="font-size: 1.2rem; font-weight: 700; color: #2563eb;">${mule.connected_accounts_count || 0}</div>
        </div>
        <div class="summary-box">
          <span style="font-size: 0.75rem; color: #64748b;">Split Transactions Pattern</span>
          <div style="font-size: 1.2rem; font-weight: 700; color: ${mule.split_transactions_detected ? '#dc2626' : '#059669'};">
            ${mule.split_transactions_detected ? 'DETECTED' : 'NONE'}
          </div>
        </div>
        <div class="summary-box">
          <span style="font-size: 0.75rem; color: #64748b;">Money Laundering Risk Score</span>
          <div style="font-size: 1.2rem; font-weight: 700; color: #dc2626;">${mule.mule_risk_score || 0}/100</div>
        </div>
      </div>
      <a href="analyst.html?query=${encodeURIComponent(data.query)}" class="btn btn-primary" style="display: inline-block; text-decoration: none;">
        Open Interactive Money Flow Graph
      </a>
    `;

  } else if (modKey === 'credential_stuffing') {
    const cs = mods.credential_stuffing || {};
    container.innerHTML = `
      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1.25rem;">
        <div class="summary-box">
          <span style="font-size: 0.75rem; color: #64748b;">Failed Login Attempts</span>
          <div style="font-size: 1.2rem; font-weight: 700; color: #dc2626;">${cs.failed_login_attempts_count || 0}</div>
        </div>
        <div class="summary-box">
          <span style="font-size: 0.75rem; color: #64748b;">Password Spray Detected?</span>
          <div style="font-size: 1.2rem; font-weight: 700; color: ${cs.password_spray_detected ? '#dc2626' : '#059669'};">
            ${cs.password_spray_detected ? 'YES (SPRAY ATTACK)' : 'NO'}
          </div>
        </div>
      </div>
    `;

  } else if (modKey === 'card_fraud') {
    const card = mods.card_fraud || {};
    container.innerHTML = `
      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1.25rem;">
        <div class="summary-box">
          <span style="font-size: 0.75rem; color: #64748b;">High-Value Transfers</span>
          <div style="font-size: 1.2rem; font-weight: 700; color: #dc2626;">${(card.high_value_transactions || []).length}</div>
        </div>
        <div class="summary-box">
          <span style="font-size: 0.75rem; color: #64748b;">Location Changes Count</span>
          <div style="font-size: 1.2rem; font-weight: 700; color: #2563eb;">${card.location_changes_count || 1}</div>
        </div>
      </div>
    `;

  } else if (modKey === 'synthetic_identity') {
    const syn = mods.synthetic_identity || {};
    container.innerHTML = `
      <div style="background: #f8fafc; padding: 1rem; border-radius: 6px; border: 1px solid #e2e8f0;">
        <div><strong>KYC Status:</strong> <span style="color: #059669; font-weight: 700;">${syn.kyc_verification_status}</span></div>
        <div><strong>Document Verification:</strong> ${syn.document_verification}</div>
        <div><strong>Identity Modifications Count:</strong> ${syn.identity_changes_count}</div>
      </div>
    `;

  } else if (modKey === 'api_abuse') {
    const api = mods.api_abuse || {};
    container.innerHTML = `
      <div style="background: #f8fafc; padding: 1rem; border-radius: 6px; border: 1px solid #e2e8f0;">
        <div><strong>Total API Requests:</strong> ${api.total_api_requests}</div>
        <div><strong>Rate Limit Violations:</strong> ${api.rate_limit_violations}</div>
        <div><strong>Unauthorized API Requests:</strong> ${api.unauthorized_requests}</div>
      </div>
    `;

  } else if (modKey === 'insider_threat') {
    const ins = mods.insider_threat || {};
    container.innerHTML = `
      <div style="background: #f8fafc; padding: 1rem; border-radius: 6px; border: 1px solid #e2e8f0;">
        <div><strong>Privilege Changes:</strong> ${ins.privilege_changes_count}</div>
        <div><strong>Administrative Overrides:</strong> ${ins.manual_overrides_count}</div>
      </div>
    `;

  } else if (modKey === 'device_intelligence') {
    const dev = mods.device_intelligence || {};
    container.innerHTML = `
      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1.25rem;">
        <div class="summary-box">
          <span style="font-size: 0.75rem; color: #64748b;">Device Trust Score</span>
          <div style="font-size: 1.2rem; font-weight: 700; color: #059669;">${dev.device_trust_score}/100</div>
        </div>
        <div class="summary-box">
          <span style="font-size: 0.75rem; color: #64748b;">Device Reuse Across Accounts</span>
          <div style="font-size: 1.2rem; font-weight: 700; color: ${dev.device_reuse_detected ? '#dc2626' : '#059669'};">
            ${dev.device_reuse_detected ? `DETECTED (${dev.colliding_accounts_count})` : 'NONE'}
          </div>
        </div>
      </div>
    `;
  }
}

/**
 * Open Session Inspection Drawer
 */
window.openSessionDrawer = function(sessionId) {
  if (!intelContext) return;
  const s = intelContext.sessions.find(x => x.session_id === sessionId);
  if (!s) return;

  const panel = document.getElementById('side-panel');
  const title = document.getElementById('sp-title');
  const body = document.getElementById('sp-body');

  if (title) title.textContent = `Session Details: ${s.session_id}`;
  if (body) {
    body.innerHTML = `
      <div style="background: #f8fafc; padding: 1rem; border-radius: 6px; border: 1px solid #e2e8f0; margin-bottom: 1rem;">
        <div><strong>Login Time:</strong> ${new Date(s.login_time).toLocaleString()}</div>
        <div><strong>IP Address:</strong> <span style="color: #2563eb;">${s.ip_address}</span></div>
        <div><strong>Device & Browser:</strong> ${s.device} (${s.browser})</div>
        <div><strong>Location:</strong> ${s.location}</div>
        <div><strong>Risk Score:</strong> <span style="color: #dc2626; font-weight: 700;">${s.risk_score}/100</span></div>
        <div><strong>Decision:</strong> <span class="badge badge-low">${s.decision}</span></div>
      </div>
    `;
  }

  panel?.classList.add('open');
};

function closeSidePanel() {
  document.getElementById('side-panel')?.classList.remove('open');
}

window.executeAnalystAction = async function(actionType) {
  if (!intelContext || !intelContext.identity) return;
  const statusMsg = document.getElementById('action-status-msg');

  try {
    const res = await fetch('/api/analyst/action', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        targetUserId: intelContext.identity.user_id,
        action: actionType,
        notes: `Executed ${actionType} from Unified Threat Intelligence Dashboard.`
      })
    });

    const data = await res.json();
    if (statusMsg) {
      statusMsg.style.display = 'block';
      if (res.ok && data.success) {
        statusMsg.style.color = '#059669';
        statusMsg.textContent = `✅ Action '${actionType}' recorded in database audit trail.`;
      } else {
        statusMsg.style.color = '#dc2626';
        statusMsg.textContent = `❌ Action failed: ${data.message || 'Error'}`;
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
