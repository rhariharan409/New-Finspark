/**
 * FINSPARK - Analyst Portal & Real-Time Money Flow Analysis Controller
 * Provides Account Investigation, Dynamic Session Aggregations, Real-Time Directed Money Flow Visualization, Time Range Filtering, Connection Details Modal, and Structuring Alerts.
 */

let currentInvestigationData = null;
let currentSelectedRange = 'all';
let autoRefreshTimer = null;

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

  // Bind Logout Button
  const logoutBtn = document.getElementById('analyst-logout-btn');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', async () => {
      if (autoRefreshTimer) clearInterval(autoRefreshTimer);
      try { await fetch('/api/analyst/logout', { method: 'POST' }); } catch (err) {}
      window.location.href = 'analyst-login.html';
    });
  }

  // Bind Search Form
  const form = document.getElementById('analyst-search-form');
  const queryInput = document.getElementById('analyst-query-input');
  const alertEl = document.getElementById('analyst-search-alert');

  if (form) {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (alertEl) alertEl.style.display = 'none';

      const query = queryInput.value.trim();
      if (!query) return;

      const submitBtn = document.getElementById('analyst-search-btn');
      submitBtn.disabled = true;
      submitBtn.textContent = 'Investigating...';

      await executeInvestigation(query, true);
      submitBtn.disabled = false;
      submitBtn.textContent = 'Investigate Account';
    });
  }

  // Bind Time Filter Buttons
  const filterBtns = document.querySelectorAll('.time-filter-btn');
  filterBtns.forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      filterBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      currentSelectedRange = btn.getAttribute('data-range') || 'all';

      if (currentInvestigationData) {
        renderMoneyFlowSection(currentInvestigationData, currentSelectedRange);
      }
    });
  });

  // Bind Connection Modal Close Button
  const modalCloseBtn = document.getElementById('modal-close-btn');
  const modalOverlay = document.getElementById('connection-modal');
  if (modalCloseBtn && modalOverlay) {
    modalCloseBtn.addEventListener('click', () => { modalOverlay.style.display = 'none'; });
    modalOverlay.addEventListener('click', (e) => {
      if (e.target === modalOverlay) modalOverlay.style.display = 'none';
    });
  }

  // Start periodic 6s silent refresh
  autoRefreshTimer = setInterval(async () => {
    if (currentInvestigationData && currentInvestigationData.query) {
      await executeInvestigation(currentInvestigationData.query, false);
    }
  }, 6000);
}

async function executeInvestigation(query, isManualSearch = false) {
  const alertEl = document.getElementById('analyst-search-alert');
  try {
    const res = await fetch(`/api/analyst/investigate?accountNumber=${encodeURIComponent(query)}`);
    const data = await res.json();

    if (!res.ok || !data.found || !data.identity) {
      if (isManualSearch) {
        document.getElementById('investigation-workspace').style.display = 'none';
        if (alertEl) {
          alertEl.textContent = data.message || `No database record found for account '${query}'.`;
          alertEl.style.display = 'block';
        }
      }
      return;
    }

    currentInvestigationData = data;
    renderInvestigationData(data, isManualSearch);

  } catch (err) {
    if (isManualSearch && alertEl) {
      alertEl.textContent = 'Network error executing account investigation query.';
      alertEl.style.display = 'block';
    }
  }
}

function renderInvestigationData(data, shouldScroll = false) {
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

  // 2. MONEY FLOW ANALYSIS SECTION
  renderMoneyFlowSection(data, currentSelectedRange);

  // 3. Session Analysis & Aggregation Table (Fixed to use backend dynamic session summaries)
  const sessionBody = document.getElementById('session-table-body');
  const sessionBadge = document.getElementById('session-count-badge');
  const sessionList = data.session_summaries || [];
  if (sessionBadge) sessionBadge.textContent = `${sessionList.length} Sessions`;

  if (sessionList.length === 0) {
    sessionBody.innerHTML = `<tr><td colspan="10" style="text-align:center; color:#64748b;">No session records available</td></tr>`;
  } else {
    sessionBody.innerHTML = sessionList.map(s => {
      const durationStr = s.session_duration_seconds ? `${s.session_duration_seconds}s` : 'Active';
      const loginTime = new Date(s.login_time).toLocaleString();
      const logoutTime = s.logout_time ? new Date(s.logout_time).toLocaleString() : 'Active Session';
      const levelClass = s.session_risk_level === 'HIGH' ? 'badge-high' : (s.session_risk_level === 'MEDIUM' ? 'badge-medium' : 'badge-low');

      return `
        <tr>
          <td><strong>${s.session_id}</strong></td>
          <td>${loginTime}</td>
          <td>${logoutTime}</td>
          <td>${durationStr}</td>
          <td><strong>${s.transaction_count}</strong></td>
          <td style="font-weight:700; color:#059669;">₹${(s.total_amount_transacted || 0).toFixed(2)}</td>
          <td>₹${(s.average_transaction_amount || 0).toFixed(2)}</td>
          <td>₹${(s.largest_transaction_amount || 0).toFixed(2)}</td>
          <td>${s.unique_receiver_count || 0}</td>
          <td><span class="badge ${levelClass}">${s.session_risk_level || 'LOW'} (${s.session_risk_score || 0})</span></td>
        </tr>
      `;
    }).join('');
  }

  // 4. Transaction Analysis Table
  const txBody = document.getElementById('tx-table-body');
  const txBadge = document.getElementById('tx-count-badge');
  const txList = tx.transactions_list || [];
  if (txBadge) txBadge.textContent = `${txList.length} Transactions`;

  const usersMap = data.users_map || {};

  if (txList.length === 0) {
    txBody.innerHTML = `<tr><td colspan="8" style="text-align:center; color:#64748b;">No transactions available</td></tr>`;
  } else {
    txBody.innerHTML = txList.map(t => {
      const isSender = t.sender_user_id === id.user_id;
      const senderName = usersMap[t.sender_user_id]?.full_name || t.sender_user_id;
      const recvName = usersMap[t.receiver_user_id]?.full_name || t.receiver_user_id;
      const levelClass = t.risk_level === 'CRITICAL' ? 'badge-critical' : (t.risk_level === 'HIGH' ? 'badge-high' : (t.risk_level === 'MEDIUM' ? 'badge-medium' : 'badge-low'));

      return `
        <tr>
          <td><strong>${t.transaction_id}</strong></td>
          <td>${senderName}</td>
          <td>${recvName}</td>
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

  // 5. Behavioral Analysis & Structuring Detection
  const base = data.baseline_comparison;
  document.getElementById('beh-base-avg').textContent = `₹${(base.historical_baseline?.average_transaction_amount || 0).toFixed(2)}`;
  document.getElementById('beh-curr-dev').textContent = `${base.current_activity?.deviation_ratio || 1.0}x`;
  document.getElementById('beh-explanation').textContent = base.explanation;

  // Risk Decision Summary
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

  if (shouldScroll) {
    window.scrollTo({ top: workspace.offsetTop - 80, behavior: 'smooth' });
  }
}

/**
 * Renders the Real-Time Database-Driven Money Flow Analysis Section
 */
function renderMoneyFlowSection(data, range = 'all') {
  const canvas = document.getElementById('money-flow-canvas');
  if (!canvas || !data || !data.transactions) return;

  const targetUser = data.identity;
  const usersMap = data.users_map || {};
  const allTxns = data.transactions.transactions_list || [];

  // Filter transactions by selected time range
  const nowMs = Date.now();
  let timeLimitMs = 0;
  let rangeLabel = 'ALL TIME';

  if (range === '1h') { timeLimitMs = 60 * 60 * 1000; rangeLabel = 'LAST 1 HOUR'; }
  else if (range === '10h') { timeLimitMs = 10 * 60 * 60 * 1000; rangeLabel = 'LAST 10 HOURS'; }
  else if (range === '24h') { timeLimitMs = 24 * 60 * 60 * 1000; rangeLabel = 'LAST 24 HOURS'; }
  else if (range === '7d') { timeLimitMs = 7 * 24 * 60 * 60 * 1000; rangeLabel = 'LAST 7 DAYS'; }

  const filteredTxns = timeLimitMs > 0
    ? allTxns.filter(t => (nowMs - new Date(t.transaction_timestamp || t.created_at).getTime()) <= timeLimitMs)
    : allTxns;

  // Update Summary Metrics
  document.getElementById('flow-period-val').textContent = rangeLabel;
  document.getElementById('flow-total-txns').textContent = filteredTxns.length;

  const totalAmount = filteredTxns.reduce((sum, t) => sum + (parseFloat(t.amount) || 0), 0);
  document.getElementById('flow-total-amount').textContent = `₹${totalAmount.toFixed(2)}`;

  const sendersSet = new Set(filteredTxns.map(t => t.sender_user_id).filter(Boolean));
  const receiversSet = new Set(filteredTxns.map(t => t.receiver_user_id).filter(Boolean));
  document.getElementById('flow-senders-count').textContent = sendersSet.size;
  document.getElementById('flow-receivers-count').textContent = receiversSet.size;

  // Most Active Sender & Receiver calculation
  const senderCounts = {};
  const receiverCounts = {};
  let maxTxAmount = 0;

  filteredTxns.forEach(t => {
    const amt = parseFloat(t.amount) || 0;
    if (amt > maxTxAmount) maxTxAmount = amt;
    senderCounts[t.sender_user_id] = (senderCounts[t.sender_user_id] || 0) + 1;
    receiverCounts[t.receiver_user_id] = (receiverCounts[t.receiver_user_id] || 0) + 1;
  });

  let topSenderId = Object.keys(senderCounts).sort((a,b) => senderCounts[b] - senderCounts[a])[0];
  let topReceiverId = Object.keys(receiverCounts).sort((a,b) => receiverCounts[b] - receiverCounts[a])[0];

  const topSenderName = topSenderId ? (usersMap[topSenderId]?.full_name || topSenderId) : 'None';
  const topReceiverName = topReceiverId ? (usersMap[topReceiverId]?.full_name || topReceiverId) : 'None';

  document.getElementById('flow-top-sender').textContent = topSenderName;
  document.getElementById('flow-top-receiver').textContent = topReceiverName;
  document.getElementById('flow-largest-tx').textContent = `₹${maxTxAmount.toFixed(2)}`;

  // Transaction Splitting / Structuring Detector on filtered subset
  const splittingAlert = document.getElementById('flow-splitting-alert');
  const splittingText = document.getElementById('flow-splitting-text');
  let splitDetected = false;

  // Group transfers by pair (sender -> receiver)
  const edgePairs = {};
  filteredTxns.forEach(t => {
    const key = `${t.sender_user_id}--->${t.receiver_user_id}`;
    if (!edgePairs[key]) {
      edgePairs[key] = {
        sender_id: t.sender_user_id,
        receiver_id: t.receiver_user_id,
        sender_name: usersMap[t.sender_user_id]?.full_name || usersMap[t.sender_user_id]?.account_id || t.sender_user_id,
        receiver_name: usersMap[t.receiver_user_id]?.full_name || usersMap[t.receiver_user_id]?.account_id || t.receiver_user_id,
        transactions: [],
        total_amount: 0
      };
    }
    edgePairs[key].transactions.push(t);
    edgePairs[key].total_amount += parseFloat(t.amount) || 0;
  });

  const pairKeys = Object.keys(edgePairs);
  for (const k of pairKeys) {
    const pair = edgePairs[k];
    if (pair.transactions.length >= 3) {
      splitDetected = true;
      if (splittingText) {
        splittingText.textContent = `Repeated transfer pattern detected: ${pair.transactions.length} transactions totaling ₹${pair.total_amount.toFixed(2)} between ${pair.sender_name} ➔ ${pair.receiver_name}.`;
      }
      break;
    }
  }

  if (splittingAlert) {
    splittingAlert.style.display = splitDetected ? 'block' : 'none';
  }

  // Render Directed Money Flow Graph Nodes & Edges
  if (filteredTxns.length === 0) {
    canvas.innerHTML = `
      <div style="text-align: center; color: #64748b; padding: 3rem 1rem;">
        <div style="font-size: 1.1rem; font-weight: 600; color: #0f172a; margin-bottom: 0.35rem;">No Money Transfers Recorded for Selected Time Period (${rangeLabel})</div>
        <p style="font-size: 0.85rem;">Select another time range or execute a transfer in User Banking to see real-time flow.</p>
      </div>
    `;
    return;
  }

  // Separate incoming senders and outgoing receivers for searched target user
  const targetUserId = targetUser.user_id;
  const targetName = targetUser.full_name || targetUser.account_id;

  const incomingSenders = [];
  const outgoingReceivers = [];

  pairKeys.forEach(k => {
    const pair = edgePairs[k];
    if (pair.receiver_id === targetUserId) {
      incomingSenders.push(pair);
    } else if (pair.sender_id === targetUserId) {
      outgoingReceivers.push(pair);
    }
  });

  let graphHTML = `<div style="display: flex; flex-direction: column; gap: 2rem; width: 100%;">`;

  // Incoming Money Flow Section (Senders ---> Target User)
  if (incomingSenders.length > 0) {
    graphHTML += `
      <div>
        <div style="font-size: 0.85rem; font-weight: 700; color: #059669; margin-bottom: 0.75rem; text-transform: uppercase; letter-spacing: 0.5px;">
          ⬇ MONEY RECEIVED BY ${targetName.toUpperCase()}
        </div>
        <div style="display: flex; flex-direction: column; gap: 0.85rem;">
          ${incomingSenders.map((pair, idx) => {
            const lastTx = pair.transactions[0];
            const riskColor = pair.total_amount >= 50000 ? '#dc2626' : (pair.transactions.length >= 3 ? '#d97706' : '#2563eb');
            const encodedKey = encodeURIComponent(JSON.stringify({ pairKey: `${pair.sender_id}--->${pair.receiver_id}`, range }));

            return `
              <div style="display: flex; align-items: center; justify-content: space-between; background: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 1rem; flex-wrap: wrap; gap: 1rem; box-shadow: 0 1px 3px rgba(0,0,0,0.04);">
                
                <!-- Sender Node -->
                <div class="flow-node">
                  <span style="font-size: 0.75rem; color: #64748b; font-weight: 600;">SENDER</span>
                  <strong style="font-size: 0.95rem; color: #0f172a; margin-top: 0.15rem;">${pair.sender_name}</strong>
                  <span style="font-size: 0.7rem; color: #64748b; margin-top: 0.1rem;">${pair.sender_id}</span>
                </div>

                <!-- Directed Money Arrow Edge Box -->
                <div class="flow-edge-box" onclick="openConnectionModal('${encodedKey}')" style="border-left: 4px solid ${riskColor}; text-align: center; flex: 1; min-width: 220px;">
                  <div style="font-size: 0.75rem; color: #64748b; font-weight: 600;">DIRECTED TRANSFER FLOW ──▶</div>
                  <div style="font-size: 1.15rem; font-weight: 800; color: ${riskColor}; margin: 0.15rem 0;">
                    ₹${pair.total_amount.toFixed(2)}
                  </div>
                  <div style="font-size: 0.75rem; color: #475569;">
                    <strong>${pair.transactions.length}</strong> transaction${pair.transactions.length > 1 ? 's' : ''} | Last: ${new Date(lastTx.transaction_timestamp || lastTx.created_at).toLocaleTimeString()}
                  </div>
                  <div style="font-size: 0.7rem; color: #2563eb; margin-top: 0.25rem; font-weight: 600;">🔍 Click to view breakdown</div>
                </div>

                <!-- Target Receiver Node -->
                <div class="flow-node target-user">
                  <span style="font-size: 0.75rem; color: #059669; font-weight: 700;">TARGET RECEIVER</span>
                  <strong style="font-size: 0.95rem; color: #065f46; margin-top: 0.15rem;">${targetName}</strong>
                  <span style="font-size: 0.7rem; color: #047857; margin-top: 0.1rem;">${targetUserId}</span>
                </div>

              </div>
            `;
          }).join('')}
        </div>
      </div>
    `;
  }

  // Outgoing Money Flow Section (Target User ---> Receivers)
  if (outgoingReceivers.length > 0) {
    graphHTML += `
      <div>
        <div style="font-size: 0.85rem; font-weight: 700; color: #2563eb; margin-bottom: 0.75rem; text-transform: uppercase; letter-spacing: 0.5px;">
          ⬆ MONEY SENT BY ${targetName.toUpperCase()}
        </div>
        <div style="display: flex; flex-direction: column; gap: 0.85rem;">
          ${outgoingReceivers.map((pair) => {
            const lastTx = pair.transactions[0];
            const riskColor = pair.total_amount >= 50000 ? '#dc2626' : (pair.transactions.length >= 3 ? '#d97706' : '#2563eb');
            const encodedKey = encodeURIComponent(JSON.stringify({ pairKey: `${pair.sender_id}--->${pair.receiver_id}`, range }));

            return `
              <div style="display: flex; align-items: center; justify-content: space-between; background: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 1rem; flex-wrap: wrap; gap: 1rem; box-shadow: 0 1px 3px rgba(0,0,0,0.04);">
                
                <!-- Target Sender Node -->
                <div class="flow-node target-user">
                  <span style="font-size: 0.75rem; color: #059669; font-weight: 700;">TARGET SENDER</span>
                  <strong style="font-size: 0.95rem; color: #065f46; margin-top: 0.15rem;">${targetName}</strong>
                  <span style="font-size: 0.7rem; color: #047857; margin-top: 0.1rem;">${targetUserId}</span>
                </div>

                <!-- Directed Money Arrow Edge Box -->
                <div class="flow-edge-box" onclick="openConnectionModal('${encodedKey}')" style="border-left: 4px solid ${riskColor}; text-align: center; flex: 1; min-width: 220px;">
                  <div style="font-size: 0.75rem; color: #64748b; font-weight: 600;">DIRECTED TRANSFER FLOW ──▶</div>
                  <div style="font-size: 1.15rem; font-weight: 800; color: ${riskColor}; margin: 0.15rem 0;">
                    ₹${pair.total_amount.toFixed(2)}
                  </div>
                  <div style="font-size: 0.75rem; color: #475569;">
                    <strong>${pair.transactions.length}</strong> transaction${pair.transactions.length > 1 ? 's' : ''} | Last: ${new Date(lastTx.transaction_timestamp || lastTx.created_at).toLocaleTimeString()}
                  </div>
                  <div style="font-size: 0.7rem; color: #2563eb; margin-top: 0.25rem; font-weight: 600;">🔍 Click to view breakdown</div>
                </div>

                <!-- Receiver Node -->
                <div class="flow-node">
                  <span style="font-size: 0.75rem; color: #64748b; font-weight: 600;">RECEIVER</span>
                  <strong style="font-size: 0.95rem; color: #0f172a; margin-top: 0.15rem;">${pair.receiver_name}</strong>
                  <span style="font-size: 0.7rem; color: #64748b; margin-top: 0.1rem;">${pair.receiver_id}</span>
                </div>

              </div>
            `;
          }).join('')}
        </div>
      </div>
    `;
  }

  graphHTML += `</div>`;
  canvas.innerHTML = graphHTML;
}

/**
 * Opens Interactive Connection Modal showing individual transactions between sender and receiver
 */
window.openConnectionModal = function(encodedData) {
  if (!currentInvestigationData) return;

  try {
    const { pairKey, range } = JSON.parse(decodeURIComponent(encodedData));
    const [senderId, receiverId] = pairKey.split('--->');
    const usersMap = currentInvestigationData.users_map || {};
    const allTxns = currentInvestigationData.transactions.transactions_list || [];

    const nowMs = Date.now();
    let timeLimitMs = 0;
    if (range === '1h') timeLimitMs = 60 * 60 * 1000;
    else if (range === '10h') timeLimitMs = 10 * 60 * 60 * 1000;
    else if (range === '24h') timeLimitMs = 24 * 60 * 60 * 1000;
    else if (range === '7d') timeLimitMs = 7 * 24 * 60 * 60 * 1000;

    const matchedTxns = allTxns.filter(t => {
      const isMatch = t.sender_user_id === senderId && t.receiver_user_id === receiverId;
      if (!isMatch) return false;
      if (timeLimitMs > 0) {
        return (nowMs - new Date(t.transaction_timestamp || t.created_at).getTime()) <= timeLimitMs;
      }
      return true;
    });

    const senderName = usersMap[senderId]?.full_name || senderId;
    const receiverName = usersMap[receiverId]?.full_name || receiverId;
    const totalAmt = matchedTxns.reduce((sum, t) => sum + (parseFloat(t.amount) || 0), 0);

    const titleEl = document.getElementById('modal-title');
    if (titleEl) titleEl.textContent = `Transfer Details: ${senderName} ➔ ${receiverName}`;

    const summaryBar = document.getElementById('modal-summary-bar');
    if (summaryBar) {
      summaryBar.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 0.5rem;">
          <div><strong>Total Flow:</strong> <span style="color: #059669; font-weight: 700; font-size: 1.05rem;">₹${totalAmt.toFixed(2)}</span></div>
          <div><strong>Transactions Count:</strong> ${matchedTxns.length}</div>
          <div><strong>Time Range:</strong> ${range.toUpperCase()}</div>
        </div>
      `;
    }

    const tableBody = document.getElementById('modal-table-body');
    if (tableBody) {
      tableBody.innerHTML = matchedTxns.map(t => `
        <tr>
          <td><strong>${t.transaction_id}</strong></td>
          <td style="font-weight:700; color:#059669;">₹${parseFloat(t.amount).toFixed(2)}</td>
          <td>${new Date(t.transaction_timestamp || t.created_at).toLocaleString()}</td>
          <td><span class="badge badge-low">${t.transaction_status || 'completed'}</span></td>
          <td><span class="badge ${t.risk_level === 'CRITICAL' ? 'badge-critical' : (t.risk_level === 'HIGH' ? 'badge-high' : 'badge-low')}">${t.risk_level || 'LOW'}</span></td>
        </tr>
      `).join('');
    }

    const modal = document.getElementById('connection-modal');
    if (modal) modal.style.display = 'flex';

  } catch (err) {
    console.error('Open connection modal error:', err);
  }
};
