/**
 * User Banking Dashboard UI Controller
 * Manages clean user-facing banking interactions: Account Info, Transfer Execution, Customer Security Alerts, Transaction History, and ATO Verification Approval Prompts.
 */

document.addEventListener('DOMContentLoaded', () => {
  initDashboard();
});

let currentUserId = null;
let pollApprovalInterval = null;

async function initDashboard() {
  const welcomeName = document.getElementById('dash-welcome-name');
  const userEmail = document.getElementById('dash-user-email');
  const accountId = document.getElementById('dash-account-id');
  const logoutBtn = document.getElementById('logout-btn');
  const txnForm = document.getElementById('txn-form');

  // 1. Verify User Session & Load Profile
  try {
    const res = await fetch('/api/auth/me');
    const data = await res.json();

    if (!res.ok || !data.authenticated || !data.user) {
      window.location.href = 'login.html';
      return;
    }

    const u = data.user;
    currentUserId = u.user_id;

    if (welcomeName) welcomeName.textContent = `Welcome, ${u.full_name || 'Valued Customer'}`;
    if (userEmail) userEmail.textContent = u.email || 'user@domain.com';
    if (accountId) accountId.textContent = u.account_id || 'TURTLE-0000000000';

    // Update Live Session Correlated Risk Widget
    if (data.sessionRiskContext || data.sessionIntegrity) {
      const score = data.sessionRiskContext?.combinedScore || data.sessionIntegrity?.riskScore || 0;
      const preAuth = data.sessionRiskContext?.preAuth || {};
      const rules = preAuth.rulesTriggered || (data.sessionIntegrity?.evidence?.triggeredRules || []).map(r => r.ruleName || r.ruleId);
      const level = data.sessionIntegrity?.action === 'BLOCK' ? 'CRITICAL (BLOCK)' : (score >= 70 ? 'CRITICAL (BLOCK)' : (score >= 45 ? 'HIGH (REVIEW)' : (score > 0 ? 'MEDIUM (MONITOR)' : 'LOW (ALLOW)')));
      updateDashboardRiskWidget(score, level, rules);
    }

    // 2. Load User Banking Transaction History
    await loadTransactionHistory();

    // 3. Start Polling for Real-Time ATO Approvals
    startPendingApprovalsPolling();

  } catch (err) {
    console.error('Session check error:', err);
    window.location.href = 'login.html';
    return;
  }

  // Bind Reset Threat Button
  const resetBtn = document.getElementById('dash-reset-threat-btn');
  if (resetBtn) {
    resetBtn.addEventListener('click', async () => {
      try {
        const res = await fetch('/api/auth/reset-threat-stores', { method: 'POST' });
        const data = await res.json();
        if (data.success) {
          updateDashboardRiskWidget(0, 'LOW (ALLOW)', []);
          showTxnAlert('🧹 Threat stores cleared. Session risk score reset to 0.', 'success');
        }
      } catch (e) {
        console.error('Reset error:', e);
      }
    });
  }

  // Bind Logout Button
  if (logoutBtn) {
    logoutBtn.addEventListener('click', async () => {
      try {
        if (pollApprovalInterval) clearInterval(pollApprovalInterval);
        await fetch('/api/auth/logout', { method: 'POST' });
      } catch (err) {}
      window.location.href = 'login.html';
    });
  }

  // Bind Send Money Form
  if (txnForm) {
    txnForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      hideTxnAlert();

      const receiverInput = document.getElementById('txn-receiver');
      const amountInput = document.getElementById('txn-amount');
      const descInput = document.getElementById('txn-description');
      const submitBtn = document.getElementById('txn-submit-btn');

      const receiver_identifier = receiverInput.value.trim();
      const amount = parseFloat(amountInput.value);
      const description = descInput ? descInput.value.trim() : '';

      if (!receiver_identifier || isNaN(amount) || amount <= 0) {
        showTxnAlert('Please provide a valid receiver account and amount.', 'danger');
        return;
      }

      submitBtn.disabled = true;
      submitBtn.textContent = 'Processing Transfer...';

      try {
        const res = await fetch('/api/transactions', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ receiver_identifier, amount, description })
        });

        const data = await res.json();
        submitBtn.disabled = false;
        submitBtn.textContent = 'Send Transfer';

        // Update Live Session Risk Widget on Transaction Result
        if (typeof data.riskScore !== 'undefined') {
          updateDashboardRiskWidget(data.riskScore, data.riskLevel, data.reasons || []);
        }

        if (!res.ok || !data.success) {
          showTxnAlert(data.message || 'Transaction could not be completed at this time. Please verify your information or contact support.', 'danger');
          return;
        }

        const msg = data.message || 'Transaction Successful';
        if (msg.includes('Under Review')) {
          showTxnAlert(msg, 'warning');
        } else {
          showTxnAlert(msg, 'success');
        }

        receiverInput.value = '';
        amountInput.value = '';
        if (descInput) descInput.value = '';
        await loadTransactionHistory();

      } catch (err) {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Send Transfer';
        showTxnAlert('Transaction could not be completed at this time. Please verify your information or contact support.', 'danger');
      }
    });
  }
}

async function loadTransactionHistory() {
  const historyContainer = document.getElementById('txn-history-list');
  if (!historyContainer) return;

  try {
    const res = await fetch('/api/transactions');
    const data = await res.json();

    if (!res.ok || !data.transactions || data.transactions.length === 0) {
      historyContainer.innerHTML = `<p style="color: #64748b; font-size: 0.85rem;">No transactions found.</p>`;
      return;
    }

    // Render history
    historyContainer.innerHTML = data.transactions.map(t => {
      const isSent = t.type === 'SENT';
      const formattedDate = new Date(t.timestamp).toLocaleString();
      const amountColor = isSent ? '#ef4444' : '#10b981';
      const dirLabel = isSent ? `Sent to ${t.counterparty}` : `Received from ${t.counterparty}`;

      return `
        <div style="padding: 0.85rem 0; border-bottom: 1px solid #e2e8f0; display: flex; justify-content: space-between; align-items: center;">
          <div>
            <strong style="font-size: 0.9rem; color: #0f172a;">${dirLabel}</strong>
            <div style="font-size: 0.75rem; color: #64748b; margin-top: 0.15rem;">
              Date: ${formattedDate} | Status: <span style="font-weight: 600; color: #334155;">${(t.status || 'completed').toUpperCase()}</span>
            </div>
            ${t.description ? `<div style="font-size: 0.75rem; color: #475569; margin-top: 0.1rem; font-style: italic;">"${t.description}"</div>` : ''}
          </div>
          <div style="font-size: 1.05rem; font-weight: 700; color: ${amountColor};">
            ${isSent ? '-' : '+'} ₹${parseFloat(t.amount).toFixed(2)}
          </div>
        </div>
      `;
    }).join('');

  } catch (err) {
    console.error('Load transaction history error:', err);
  }
}

/**
 * Real-Time Polling for Pending ATO Verification Approval Requests
 */
function startPendingApprovalsPolling() {
  checkPendingApprovals();
  if (pollApprovalInterval) clearInterval(pollApprovalInterval);
  pollApprovalInterval = setInterval(checkPendingApprovals, 2000);
}

async function checkPendingApprovals() {
  const container = document.getElementById('ato-approval-container');
  if (!container) return;

  try {
    const res = await fetch('/api/transactions/pending-ato-approvals');
    const data = await res.json();

    if (!res.ok || !data.pendingRequests || data.pendingRequests.length === 0) {
      container.style.display = 'none';
      container.innerHTML = '';
      return;
    }

    const pendingReq = data.pendingRequests[0];
    renderApprovalCard(pendingReq);

  } catch (e) {
    console.error('Error fetching pending approvals:', e);
  }
}

function renderApprovalCard(req) {
  const container = document.getElementById('ato-approval-container');
  if (!container) return;

  const currentReqId = container.getAttribute('data-req-id');
  if (currentReqId === req.ato_request_id && container.style.display === 'block') {
    // Already rendering this exact request
    return;
  }

  container.setAttribute('data-req-id', req.ato_request_id);

  const formattedAmount = `₹${parseFloat(req.amount).toLocaleString()}`;
  const receiverName = req.receiver_identifier || req.receiver_user_id || 'Recipient';

  container.innerHTML = `
    <div class="card" style="padding: 1.75rem; border-top: 4px solid #d97706; background: #fffdf5; border-color: #fde68a; box-shadow: 0 10px 25px rgba(217,119,6,0.12);">
      
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
        <h3 style="margin: 0; font-size: 1.15rem; color: #92400e; font-weight: 800; letter-spacing: 0.03em;">
          TRANSACTION APPROVAL REQUIRED
        </h3>
        <span style="font-size: 0.75rem; background: #fef3c7; color: #92400e; padding: 0.25rem 0.6rem; border-radius: 4px; font-weight: 700;">
          SECURITY VERIFICATION
        </span>
      </div>

      <p style="color: #78350f; font-size: 0.92rem; margin-bottom: 1.25rem; font-weight: 600;">
        A transaction is attempting to use your account.
      </p>

      <div style="background: #ffffff; border: 1px solid #fde68a; border-radius: 6px; padding: 1rem; margin-bottom: 1.25rem; font-size: 0.9rem; color: #334155; line-height: 1.8;">
        <div><strong>Amount:</strong> <span style="font-weight: 800; color: #0f172a; font-size: 1.05rem;">${formattedAmount}</span></div>
        <div><strong>Receiver:</strong> <span style="font-weight: 700; color: #2563eb;">${receiverName}</span></div>
        <div><strong>Transaction ID:</strong> <code style="color: #475569; font-weight: 600;">${req.transaction_id}</code></div>
        <div><strong>Initiating Session:</strong> <code style="color: #475569; font-weight: 600;">${req.session_id}</code></div>
      </div>

      <div style="font-weight: 700; color: #0f172a; font-size: 0.95rem; margin-bottom: 1rem;">
        Question: Did you initiate this transaction?
      </div>

      <div style="display: flex; gap: 0.75rem; flex-wrap: wrap;">
        <button type="button" id="btn-approve-ato" class="btn btn-primary" style="padding: 0.7rem 1.35rem; font-weight: 700; background: #059669; border-color: #059669;">
          YES, APPROVE TRANSACTION
        </button>
        <button type="button" id="btn-deny-ato" class="btn btn-danger" style="padding: 0.7rem 1.35rem; font-weight: 700; background: #dc2626; border-color: #dc2626;">
          NO, THIS WAS NOT ME
        </button>
      </div>

      <div id="ato-approval-feedback" style="display: none; margin-top: 1rem; font-size: 0.88rem; font-weight: 600;"></div>
    </div>
  `;

  container.style.display = 'block';

  // Bind Approve / Deny Buttons
  const approveBtn = document.getElementById('btn-approve-ato');
  const denyBtn = document.getElementById('btn-deny-ato');
  const feedbackEl = document.getElementById('ato-approval-feedback');

  if (approveBtn) {
    approveBtn.addEventListener('click', async () => {
      approveBtn.disabled = true;
      denyBtn.disabled = true;
      approveBtn.textContent = 'Approving...';

      try {
        const res = await fetch('/api/transactions/respond-ato-approval', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            requestId: req.ato_request_id,
            approvalDecision: 'APPROVE',
            amount: req.amount,
            receiverIdentifier: req.receiver_user_id
          })
        });
        const data = await res.json();

        if (res.ok && data.success) {
          if (feedbackEl) {
            feedbackEl.style.color = '#059669';
            feedbackEl.textContent = '✓ Transaction approved successfully.';
            feedbackEl.style.display = 'block';
          }
          setTimeout(() => {
            container.style.display = 'none';
            container.innerHTML = '';
            loadTransactionHistory();
          }, 1500);
        } else {
          if (feedbackEl) {
            feedbackEl.style.color = '#dc2626';
            feedbackEl.textContent = data.message || 'Failed to approve transaction.';
            feedbackEl.style.display = 'block';
          }
          approveBtn.disabled = false;
          denyBtn.disabled = false;
          approveBtn.textContent = 'YES, APPROVE TRANSACTION';
        }
      } catch (e) {
        approveBtn.disabled = false;
        denyBtn.disabled = false;
        approveBtn.textContent = 'YES, APPROVE TRANSACTION';
      }
    });
  }

  if (denyBtn) {
    denyBtn.addEventListener('click', async () => {
      approveBtn.disabled = true;
      denyBtn.disabled = true;
      denyBtn.textContent = 'Blocking...';

      try {
        const res = await fetch('/api/transactions/respond-ato-approval', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            requestId: req.ato_request_id,
            approvalDecision: 'DENY',
            amount: req.amount,
            receiverIdentifier: req.receiver_user_id
          })
        });
        const data = await res.json();

        if (feedbackEl) {
          feedbackEl.style.color = '#dc2626';
          feedbackEl.textContent = 'Transaction blocked successfully.';
          feedbackEl.style.display = 'block';
        }

        setTimeout(() => {
          container.style.display = 'none';
          container.innerHTML = '';
          loadTransactionHistory();
        }, 1500);

      } catch (e) {
        approveBtn.disabled = false;
        denyBtn.disabled = false;
        denyBtn.textContent = 'NO, THIS WAS NOT ME';
      }
    });
  }
}

function showTxnAlert(msg, type = 'danger') {
  const alertEl = document.getElementById('txn-alert');
  if (!alertEl) return;
  alertEl.textContent = msg;
  alertEl.className = `alert alert-${type}`;
  alertEl.style.display = 'block';
}

function hideTxnAlert() {
  const alertEl = document.getElementById('txn-alert');
  if (alertEl) alertEl.style.display = 'none';
}

function updateDashboardRiskWidget(score = 0, level = 'LOW (ALLOW)', reasons = []) {
  const scoreVal = document.getElementById('dash-risk-score-val');
  const scoreBar = document.getElementById('dash-risk-score-bar');
  const riskBadge = document.getElementById('dash-risk-badge');
  const reasonsDiv = document.getElementById('dash-risk-reasons');

  if (!scoreVal || !scoreBar || !riskBadge) return;
  const numScore = Math.min(100, Math.max(0, parseFloat(score) || 0));

  scoreVal.textContent = Math.round(numScore);
  scoreBar.style.width = `${numScore}%`;

  let color = '#22c55e'; // Green
  let badgeBg = 'rgba(34, 197, 94, 0.15)';
  let badgeBorder = 'rgba(34, 197, 94, 0.3)';

  if (numScore >= 70) {
    color = '#ef4444'; // Red
    badgeBg = 'rgba(239, 68, 68, 0.2)';
    badgeBorder = 'rgba(239, 68, 68, 0.4)';
  } else if (numScore >= 45) {
    color = '#f97316'; // Orange
    badgeBg = 'rgba(249, 115, 22, 0.2)';
    badgeBorder = 'rgba(249, 115, 22, 0.4)';
  } else if (numScore > 0) {
    color = '#eab308'; // Yellow
    badgeBg = 'rgba(234, 179, 8, 0.2)';
    badgeBorder = 'rgba(234, 179, 8, 0.4)';
  }

  scoreVal.style.color = color;
  scoreBar.style.backgroundColor = color;
  riskBadge.style.color = color;
  riskBadge.style.background = badgeBg;
  riskBadge.style.borderColor = badgeBorder;
  riskBadge.textContent = level;

  if (reasonsDiv) {
    if (reasons && reasons.length > 0) {
      reasonsDiv.style.display = 'block';
      reasonsDiv.innerHTML = `<span style="color: #f87171; font-weight: 700;">⚡ Correlated Risk Signals:</span> ${reasons.join('; ')}`;
    } else {
      reasonsDiv.style.display = 'none';
      reasonsDiv.innerHTML = '';
    }
  }
}
