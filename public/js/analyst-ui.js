/**
 * FINSPARK - Analyst Portal UI Controller
 * Handles account search, session analysis, transaction analysis, baseline comparisons, transaction splitting detection, and risk decision rendering.
 */

document.addEventListener('DOMContentLoaded', () => {
  initAnalystPortal();
});

async function initAnalystPortal() {
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

  // Bind Form Elements
  const form = document.getElementById('analyst-search-form');
  const queryInput = document.getElementById('analyst-query-input');
  const alertEl = document.getElementById('analyst-search-alert');
  const logoutBtn = document.getElementById('analyst-logout-btn');

  if (logoutBtn) {
    logoutBtn.addEventListener('click', async () => {
      try { await fetch('/api/analyst/logout', { method: 'POST' }); } catch (err) {}
      window.location.href = 'analyst-login.html';
    });
  }

  if (form) {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (alertEl) alertEl.style.display = 'none';

      const query = queryInput.value.trim();
      if (!query) return;

      const submitBtn = document.getElementById('analyst-search-btn');
      submitBtn.disabled = true;
      submitBtn.textContent = 'Investigating...';

      try {
        const res = await fetch(`/api/analyst/investigate?accountNumber=${encodeURIComponent(query)}`);
        const data = await res.json();

        submitBtn.disabled = false;
        submitBtn.textContent = 'Investigate Account';

        if (!res.ok || !data.found || !data.identity) {
          document.getElementById('investigation-workspace').style.display = 'none';
          if (alertEl) {
            alertEl.textContent = data.message || `No record found in database for account '${query}'.`;
            alertEl.style.display = 'block';
          }
          return;
        }

        renderInvestigationData(data);

      } catch (err) {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Investigate Account';
        if (alertEl) {
          alertEl.textContent = 'Network error executing account investigation query.';
          alertEl.style.display = 'block';
        }
      }
    });
  }
}

function renderInvestigationData(data) {
  const workspace = document.getElementById('investigation-workspace');
  if (!workspace || !data.identity) return;

  workspace.style.display = 'block';
  const id = data.identity;
  const tx = data.transactions;
  const risk = data.risk_summary;

  // 1. Investigation Summary
  document.getElementById('sum-name').textContent = id.full_name || 'N/A';
  document.getElementById('sum-account-id').textContent = id.account_id || 'N/A';
  document.getElementById('sum-status').textContent = (id.account_status || 'active').toUpperCase();
  document.getElementById('sum-risk-score').textContent = `${risk.final_risk_score}/100`;
  document.getElementById('sum-total-amount').textContent = `₹${(tx.total_sent_amount || 0).toFixed(2)}`;
  document.getElementById('sum-total-txns').textContent = tx.total_transactions || 0;
  document.getElementById('sum-total-sessions').textContent = id.total_sessions_count || 0;

  const riskBadge = document.getElementById('overall-risk-badge');
  if (riskBadge) {
    riskBadge.textContent = `${risk.risk_level} RISK (${risk.final_risk_score}/100)`;
    riskBadge.className = risk.risk_level === 'CRITICAL' ? 'badge badge-critical' : (risk.risk_level === 'HIGH' ? 'badge badge-high' : (risk.risk_level === 'MEDIUM' ? 'badge badge-medium' : 'badge badge-low'));
  }

  // 2. Transaction Analysis Table
  const txBody = document.getElementById('tx-table-body');
  const txBadge = document.getElementById('tx-count-badge');
  const txList = tx.transactions_list || [];
  if (txBadge) txBadge.textContent = `${txList.length} Transactions`;

  if (txList.length === 0) {
    txBody.innerHTML = `<tr><td colspan="8" style="text-align:center; color:#64748b;">No transactions available</td></tr>`;
  } else {
    txBody.innerHTML = txList.map(t => {
      const isSender = t.sender_user_id === id.user_id;
      const levelClass = t.risk_level === 'CRITICAL' ? 'badge-critical' : (t.risk_level === 'HIGH' ? 'badge-high' : (t.risk_level === 'MEDIUM' ? 'badge-medium' : 'badge-low'));
      return `
        <tr>
          <td><strong>${t.transaction_id}</strong></td>
          <td>${t.sender_user_id}</td>
          <td>${t.receiver_user_id}</td>
          <td style="font-weight:700; color:${isSender ? '#dc2626' : '#059669'};">
            ${isSender ? '-' : '+'} ₹${parseFloat(t.amount).toFixed(2)}
          </td>
          <td>${new Date(t.transaction_timestamp || t.created_at).toLocaleString()}</td>
          <td>${t.session_id || 'N/A'}</td>
          <td><span class="badge ${levelClass}">${t.risk_level || 'LOW'}</span></td>
          <td><span class="badge badge-low">${t.transaction_status || 'completed'}</span></td>
        </tr>
      `;
    }).join('');
  }

  // 3. Session Analysis Table (Dynamic Aggregation per Session)
  const sessionBody = document.getElementById('session-table-body');
  const sessionBadge = document.getElementById('session-count-badge');
  const sessions = data.raw?.sessions || [];
  if (sessionBadge) sessionBadge.textContent = `${sessions.length} Sessions`;

  if (sessions.length === 0) {
    sessionBody.innerHTML = `<tr><td colspan="10" style="text-align:center; color:#64748b;">No session records available</td></tr>`;
  } else {
    sessionBody.innerHTML = sessions.map(s => {
      // Calculate dynamic session totals from transaction list
      const sessionTxns = txList.filter(t => t.session_id === s.session_id);
      const sessionTotal = sessionTxns.reduce((sum, t) => sum + (parseFloat(t.amount) || 0), 0);
      const sessionAvg = sessionTxns.length > 0 ? sessionTotal / sessionTxns.length : 0;
      const sessionMax = sessionTxns.length > 0 ? Math.max(...sessionTxns.map(t => parseFloat(t.amount) || 0)) : 0;
      const uniqueReceivers = new Set(sessionTxns.map(t => t.receiver_user_id).filter(Boolean)).size;

      const durationStr = s.session_duration_seconds ? `${s.session_duration_seconds}s` : 'Active';
      const loginTime = new Date(s.login_time).toLocaleString();
      const logoutTime = s.logout_time ? new Date(s.logout_time).toLocaleString() : 'Active Session';

      return `
        <tr>
          <td><strong>${s.session_id}</strong></td>
          <td>${loginTime}</td>
          <td>${logoutTime}</td>
          <td>${durationStr}</td>
          <td><strong>${sessionTxns.length}</strong></td>
          <td style="font-weight:700; color:#059669;">₹${sessionTotal.toFixed(2)}</td>
          <td>₹${sessionAvg.toFixed(2)}</td>
          <td>₹${sessionMax.toFixed(2)}</td>
          <td>${uniqueReceivers}</td>
          <td><span class="badge badge-low">LOW</span></td>
        </tr>
      `;
    }).join('');
  }

  // 4. Behavioral Analysis & Transaction Splitting Detection
  const base = data.baseline_comparison;
  document.getElementById('beh-base-avg').textContent = `₹${(base.historical_baseline?.average_transaction_amount || 0).toFixed(2)}`;
  document.getElementById('beh-curr-dev').textContent = `${base.current_activity?.deviation_ratio || 1.0}x`;
  document.getElementById('beh-explanation').textContent = base.explanation;

  const structBox = document.getElementById('structuring-warning-box');
  const structText = document.getElementById('structuring-warning-text');
  if (tx.structuring_analysis?.detected) {
    structText.textContent = tx.structuring_analysis.explanation;
    structBox.style.display = 'block';
  } else {
    structBox.style.display = 'none';
  }

  // 5. Risk Decision Summary
  document.getElementById('rd-score').textContent = `${risk.final_risk_score}/100`;
  const rdLevel = document.getElementById('rd-level');
  const rdDecision = document.getElementById('rd-decision');
  if (rdLevel) {
    rdLevel.textContent = risk.risk_level;
    rdLevel.className = risk.risk_level === 'CRITICAL' ? 'badge badge-critical' : (risk.risk_level === 'HIGH' ? 'badge badge-high' : (risk.risk_level === 'MEDIUM' ? 'badge badge-medium' : 'badge badge-low'));
  }
  if (rdDecision) {
    rdDecision.textContent = risk.decision;
    rdDecision.className = risk.decision === 'BLOCK' ? 'badge badge-critical' : (risk.decision === 'REVIEW' ? 'badge badge-high' : 'badge badge-low');
  }

  const signalsList = document.getElementById('rd-signals-list');
  const signals = data.xai?.analyst_technical_view?.primary_signals || ['Normal transaction behavior'];
  if (signalsList) {
    signalsList.innerHTML = signals.map(sig => `<li>${sig}</li>`).join('');
  }

  window.scrollTo({ top: workspace.offsetTop - 80, behavior: 'smooth' });
}
