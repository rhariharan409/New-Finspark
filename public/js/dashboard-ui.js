/**
 * User Banking Dashboard UI Controller
 * Manages clean user-facing banking interactions: Account Info, Transfer Execution, Customer Security Alerts, and Transaction History.
 * STRICTLY ISOLATED: Internal risk scores, decision reasoning, session IDs, and baseline analytics are NEVER rendered here.
 */

document.addEventListener('DOMContentLoaded', () => {
  initDashboard();
});

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
    if (welcomeName) welcomeName.textContent = `Welcome, ${u.full_name || 'Valued Customer'}`;
    if (userEmail) userEmail.textContent = u.email || 'user@domain.com';
    if (accountId) accountId.textContent = u.account_id || 'TURTLE-0000000000';

    // 2. Load User Banking Transaction History
    await loadTransactionHistory();

  } catch (err) {
    console.error('Session check error:', err);
    window.location.href = 'login.html';
    return;
  }

  // Bind Logout Button
  if (logoutBtn) {
    logoutBtn.addEventListener('click', async () => {
      try {
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

        if (!res.ok || !data.success) {
          showTxnAlert(data.message || 'Transaction could not be completed at this time. Please verify your information or contact support.', 'danger');
          return;
        }

        // Handle customer-safe messaging based on response
        const msg = data.message || 'Transaction Successful';
        if (msg.includes('Under Review')) {
          showTxnAlert(msg, 'warning');
        } else {
          showTxnAlert(msg, 'success');
        }

        // Reset form inputs & refresh history
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
