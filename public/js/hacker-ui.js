document.addEventListener('DOMContentLoaded', () => {
  const verifyForm = document.getElementById('ato-verify-form');
  const verifyInput = document.getElementById('verify-session-id');
  const verifyAlert = document.getElementById('ato-verify-alert');
  const verifyBtn = document.getElementById('verify-session-btn');

  const confirmModal = document.getElementById('session-confirm-modal');
  const cancelModalBtn = document.getElementById('confirm-modal-cancel');
  const continueModalBtn = document.getElementById('confirm-modal-continue');
  const modalSessionTimeEl = document.getElementById('modal-session-time');
  const modalOwnerEmailEl = document.getElementById('modal-owner-email');

  const mismatchModal = document.getElementById('verification-mismatch-modal');
  const mismatchTableBody = document.getElementById('mismatch-table-body');
  const mismatchModalCloseBtn = document.getElementById('mismatch-modal-close');

  const smsModal = document.getElementById('simulated-sms-modal');
  const smsRecipientEl = document.getElementById('sms-user-recipient');
  const smsTxnIdEl = document.getElementById('sms-txn-id');
  const smsTxnAmountEl = document.getElementById('sms-txn-amount');
  const smsTxnReceiverEl = document.getElementById('sms-txn-receiver');
  const smsTxnSessionEl = document.getElementById('sms-txn-session');
  const smsApproveBtn = document.getElementById('sms-approve-btn');
  const smsDenyBtn = document.getElementById('sms-deny-btn');

  const verificationCard = document.getElementById('ato-verification-card');
  const simulationCard = document.getElementById('ato-simulation-interface');

  const simSessionIdEl = document.getElementById('sim-session-id');
  const simForm = document.getElementById('ato-initiate-form');
  const simAlert = document.getElementById('sim-form-alert');
  const simSubmitBtn = document.getElementById('sim-submit-btn');

  const initiatorBox = document.getElementById('ato-initiator-confirmation-box');
  const pendingTxnIdEl = document.getElementById('pending-txn-id');
  const pendingTxnAmountEl = document.getElementById('pending-txn-amount');
  const pendingTxnReceiverEl = document.getElementById('pending-txn-receiver');
  const initiatorConfirmBtn = document.getElementById('initiator-confirm-btn');
  const initiatorCancelBtn = document.getElementById('initiator-cancel-btn');
  const initiatorActionButtons = document.getElementById('initiator-action-buttons');

  const statusBadge = document.getElementById('ato-status-badge');
  const statusDetail = document.getElementById('ato-status-detail');

  let activeVerifiedSessionId = null;
  let activeRequestId = null;
  let activePollInterval = null;
  let activeUserEmail = 'user@example.com';
  let activeUserPhone = '+91 9025521474';

  function showVerifyError(msg) {
    if (!verifyAlert) return;
    verifyAlert.textContent = msg;
    verifyAlert.style.display = 'block';
  }

  function hideVerifyError() {
    if (verifyAlert) verifyAlert.style.display = 'none';
  }

  // 1. Session Verification Logic & Mismatch Handling
  if (verifyForm) {
    verifyForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      hideVerifyError();

      const sessionId = verifyInput ? verifyInput.value.trim() : '';
      if (!sessionId) {
        return showVerifyError('Unable to verify session. Please enter a Session ID.');
      }

      if (verifyBtn) {
        verifyBtn.disabled = true;
        verifyBtn.textContent = 'VERIFYING...';
      }

      try {
        const res = await fetch('/api/auth/verify-session-id-login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            sessionId,
            clientEnv: {
              browserName: 'Chrome',
              operatingSystem: 'Windows 11',
              deviceFingerprint: 'FP-SIMULATED-ATTACKER'
            }
          })
        });

        const data = await res.json();
        if (verifyBtn) {
          verifyBtn.disabled = false;
          verifyBtn.textContent = 'VERIFY SESSION';
        }

        // Handle Itemized Environmental Mismatch Failures
        if (data.mismatches && data.mismatches.length > 0) {
          if (mismatchTableBody) {
            mismatchTableBody.innerHTML = data.mismatches.map(m => `
              <tr>
                <td><strong>${m.attribute} Check</strong></td>
                <td><code style="color: #059669;">${m.baseline}</code></td>
                <td><code style="color: #dc2626; font-weight: 700;">${m.incoming}</code></td>
              </tr>
            `).join('');
          }
          if (mismatchModal) mismatchModal.style.display = 'flex';
          return;
        }

        if (res.status === 404 || (data.message && (data.message.includes('non-existent') || data.message.includes('Invalid session ID')))) {
          return showVerifyError('Unable to verify session. Invalid session ID.');
        }

        if (res.status === 403 || (data.message && (data.message.includes('terminated') || data.message.includes('expired') || data.message.includes('no longer active')))) {
          return showVerifyError('Session verification failed. This session is no longer active.');
        }

        if (!res.ok || !data.success) {
          return showVerifyError(data.message || 'Unable to verify session. Invalid session ID.');
        }

        // Verified Active Session -> Store & Show Confirmation Modal with DB Starting Time
        activeVerifiedSessionId = sessionId;
        activeUserEmail = data.user?.email || 'user@example.com';

        const startTime = data.startingTime || data.loginTime || new Date().toISOString();
        const formattedTime = new Date(startTime).toLocaleString();

        if (modalSessionTimeEl) modalSessionTimeEl.textContent = formattedTime;
        if (modalOwnerEmailEl) modalOwnerEmailEl.textContent = activeUserEmail;

        // Render Live Security Panel with checks
        if (data.checks) {
          renderLiveSecurityPanel(data.checks, data.weightedRiskScore, data.riskLevel);
        }

        if (confirmModal) confirmModal.style.display = 'flex';

      } catch (err) {
        if (verifyBtn) {
          verifyBtn.disabled = false;
          verifyBtn.textContent = 'VERIFY SESSION';
        }
        showVerifyError('Unable to verify session. Network error occurred.');
      }
    });
  }

  // 2. Modal Controls
  if (mismatchModalCloseBtn) {
    mismatchModalCloseBtn.addEventListener('click', () => {
      if (mismatchModal) mismatchModal.style.display = 'none';
    });
  }

  if (cancelModalBtn) {
    cancelModalBtn.addEventListener('click', () => {
      if (confirmModal) confirmModal.style.display = 'none';
    });
  }

  if (continueModalBtn) {
    continueModalBtn.addEventListener('click', () => {
      if (confirmModal) confirmModal.style.display = 'none';
      if (verificationCard) verificationCard.style.display = 'none';
      if (simulationCard) simulationCard.style.display = 'block';
      if (simSessionIdEl) simSessionIdEl.textContent = activeVerifiedSessionId || 'SES-XXXXXXXX';
    });
  }

  // 3. Initiate Transaction & Trigger Simulated Email Modal
  if (simForm) {
    simForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (simAlert) simAlert.style.display = 'none';

      const receiver = document.getElementById('sim-receiver')?.value.trim();
      const amount = parseFloat(document.getElementById('sim-amount')?.value);
      const description = document.getElementById('sim-description')?.value.trim();

      if (!receiver || isNaN(amount) || amount <= 0) {
        if (simAlert) {
          simAlert.textContent = 'Please enter a valid receiver and amount greater than zero.';
          simAlert.style.display = 'block';
        }
        return;
      }

      if (simSubmitBtn) {
        simSubmitBtn.disabled = true;
        simSubmitBtn.textContent = 'INITIATING TRANSACTION...';
      }

      try {
        const res = await fetch('/api/transactions/initiate-ato-transaction', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            sessionId: activeVerifiedSessionId,
            receiverIdentifier: receiver,
            amount,
            description
          })
        });

        const data = await res.json();
        if (simSubmitBtn) {
          simSubmitBtn.disabled = false;
          simSubmitBtn.textContent = 'TRANSACT';
        }

        if (!res.ok || !data.success) {
          if (simAlert) {
            simAlert.textContent = data.message || 'Failed to initiate ATO transaction.';
            simAlert.style.display = 'block';
          }
          return;
        }

        const atoReq = data.atoRequest;
        activeRequestId = atoReq?.ato_request_id;
        const targetPhone = data.userPhone || activeUserPhone || '+91 98765 43210';

        // Populate Transaction Details Card
        if (pendingTxnIdEl) pendingTxnIdEl.textContent = atoReq.transaction_id || 'TXN-XXXX';
        if (pendingTxnAmountEl) pendingTxnAmountEl.textContent = `₹${parseFloat(atoReq.amount).toLocaleString()}`;
        if (pendingTxnReceiverEl) pendingTxnReceiverEl.textContent = receiver;

        if (initiatorBox) initiatorBox.style.display = 'block';
        if (initiatorActionButtons) initiatorActionButtons.style.display = 'flex';

        updateStatusUI('PENDING_VERIFICATION', 'Waiting for initiator confirmation (Click OK) and legitimate user approval...');

        // Automatically Trigger Simulated Security SMS Notification Modal ("Verify That's You")
        if (smsRecipientEl) smsRecipientEl.textContent = targetPhone;
        if (smsTxnIdEl) smsTxnIdEl.textContent = atoReq.transaction_id || 'TXN-XXXX';
        if (smsTxnAmountEl) smsTxnAmountEl.textContent = `₹${parseFloat(atoReq.amount).toLocaleString()}`;
        if (smsTxnReceiverEl) smsTxnReceiverEl.textContent = receiver;
        if (smsTxnSessionEl) smsTxnSessionEl.textContent = activeVerifiedSessionId || 'SES-XXXXXXXX';

        if (smsModal) smsModal.style.display = 'flex';

        // Start polling for real-time status updates
        startStatusPolling(activeRequestId);

      } catch (err) {
        if (simSubmitBtn) {
          simSubmitBtn.disabled = false;
          simSubmitBtn.textContent = 'TRANSACT';
        }
        if (simAlert) {
          simAlert.textContent = 'Network error initiating ATO transaction.';
          simAlert.style.display = 'block';
        }
      }
    });
  }

  // 4. Interactive SMS Security Notification Modal Handlers (YES / NO)
  if (smsApproveBtn) {
    smsApproveBtn.addEventListener('click', async () => {
      if (!activeRequestId) return;
      smsApproveBtn.disabled = true;
      smsApproveBtn.textContent = 'APPROVING...';

      try {
        const res = await fetch('/api/transactions/respond-ato-approval', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ requestId: activeRequestId, approvalDecision: 'APPROVE' })
        });
        const data = await res.json();
        smsApproveBtn.disabled = false;
        smsApproveBtn.textContent = '✅ YES, APPROVE TRANSACTION';

        if (smsModal) smsModal.style.display = 'none';

        if (res.ok && data.success) {
          updateStatusUI('COMPLETED', '🟢 Transaction Completed! Initiator confirmed, legitimate user approved via SMS alert, and risk engine allowed.');
        } else {
          alert(data.message || 'Failed to approve transaction.');
        }
      } catch (e) {
        smsApproveBtn.disabled = false;
        smsApproveBtn.textContent = '✅ YES, APPROVE TRANSACTION';
      }
    });
  }

  if (smsDenyBtn) {
    smsDenyBtn.addEventListener('click', async () => {
      if (!activeRequestId) return;
      smsDenyBtn.disabled = true;
      smsDenyBtn.textContent = 'DENYING...';

      try {
        const res = await fetch('/api/transactions/respond-ato-approval', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ requestId: activeRequestId, approvalDecision: 'DENY' })
        });
        const data = await res.json();
        smsDenyBtn.disabled = false;
        smsDenyBtn.textContent = '🚫 NO, THIS WAS NOT ME';

        if (smsModal) smsModal.style.display = 'none';

        if (res.ok && data.success) {
          updateStatusUI('BLOCKED', 'Transaction Blocked\nLegitimate user denied this transaction via SMS verification.');
        } else {
          alert(data.message || 'Failed to deny transaction.');
        }
      } catch (e) {
        smsDenyBtn.disabled = false;
        smsDenyBtn.textContent = '🚫 NO, THIS WAS NOT ME';
      }
    });
  }

  // 5. Initiator Confirm Intent Button (OK)
  if (initiatorConfirmBtn) {
    initiatorConfirmBtn.addEventListener('click', async () => {
      if (!activeRequestId) return;
      initiatorConfirmBtn.disabled = true;
      initiatorConfirmBtn.textContent = 'CONFIRMING...';

      try {
        const res = await fetch('/api/transactions/confirm-initiator-intent', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ requestId: activeRequestId, intentAction: 'CONFIRM' })
        });
        const data = await res.json();

        initiatorConfirmBtn.disabled = false;
        initiatorConfirmBtn.textContent = 'OK, CONFIRM INTENT';

        if (res.ok && data.success) {
          if (initiatorActionButtons) initiatorActionButtons.style.display = 'none';
          updateStatusFromRequest(data.atoRequest || data);
        } else {
          alert(data.message || 'Failed to confirm initiator intent.');
        }
      } catch (e) {
        initiatorConfirmBtn.disabled = false;
        initiatorConfirmBtn.textContent = 'OK, CONFIRM INTENT';
      }
    });
  }

  // 6. Initiator Cancel Button
  if (initiatorCancelBtn) {
    initiatorCancelBtn.addEventListener('click', async () => {
      if (!activeRequestId) return;
      if (!confirm('Are you sure you want to cancel this transaction?')) return;

      try {
        const res = await fetch('/api/transactions/confirm-initiator-intent', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ requestId: activeRequestId, intentAction: 'CANCEL' })
        });
        const data = await res.json();
        if (res.ok && data.success) {
          if (initiatorActionButtons) initiatorActionButtons.style.display = 'none';
          updateStatusUI('CANCELLED', 'Transaction cancelled by initiator.');
        }
      } catch (e) {}
    });
  }

  // Helper function for status UI updates
  function updateStatusUI(status, detailText) {
    if (statusBadge) {
      statusBadge.textContent = status;
      if (status === 'COMPLETED') {
        statusBadge.style.background = '#d1fae5';
        statusBadge.style.color = '#065f46';
      } else if (status === 'BLOCKED') {
        statusBadge.style.background = '#fee2e2';
        statusBadge.style.color = '#991b1b';
      } else if (status === 'EXPIRED' || status === 'CANCELLED') {
        statusBadge.style.background = '#f1f5f9';
        statusBadge.style.color = '#475569';
      } else {
        statusBadge.style.background = '#fef3c7';
        statusBadge.style.color = '#92400e';
      }
    }
    if (statusDetail) statusDetail.textContent = detailText;
  }

  function updateStatusFromRequest(req) {
    if (!req) return;
    if (req.status === 'COMPLETED') {
      if (activePollInterval) clearInterval(activePollInterval);
      updateStatusUI('COMPLETED', '🟢 Transaction Completed! Initiator confirmed, legitimate user approved, and risk engine allowed.');
    } else if (req.status === 'BLOCKED') {
      if (activePollInterval) clearInterval(activePollInterval);
      if (req.trusted_user_confirmation === 'DENIED') {
        updateStatusUI('BLOCKED', 'Transaction Blocked\nLegitimate user denied this transaction.');
      } else {
        updateStatusUI('BLOCKED', 'Transaction Blocked by risk engine or security evaluation.');
      }
    } else if (req.status === 'EXPIRED') {
      if (activePollInterval) clearInterval(activePollInterval);
      updateStatusUI('EXPIRED', 'Approval request expired. Transaction was not completed.');
    } else if (req.status === 'CANCELLED') {
      if (activePollInterval) clearInterval(activePollInterval);
      updateStatusUI('CANCELLED', 'Transaction cancelled by initiator.');
    } else {
      if (req.initiator_confirmation === 'APPROVED') {
        updateStatusUI('PENDING_USER_APPROVAL', 'Initiator confirmed intent. Waiting for legitimate user approval...');
      } else {
        updateStatusUI('PENDING_VERIFICATION', 'Waiting for initiator confirmation (Click OK) and legitimate user approval...');
      }
    }
  }

  function startStatusPolling(requestId) {
    if (activePollInterval) clearInterval(activePollInterval);
    activePollInterval = setInterval(async () => {
      if (!requestId) return;
      try {
        const pRes = await fetch(`/api/transactions/ato-request-status/${requestId}`);
        const pData = await pRes.json();
        if (pRes.ok && pData.success && pData.atoRequest) {
          updateStatusFromRequest(pData.atoRequest);
        }
      } catch (e) {}
    }, 2000);
  }

  function renderLiveSecurityPanel(checks, weightedRiskScore = 30, riskLevel = 'MEDIUM') {
    const tableBody = document.getElementById('live-checks-table-body');
    const riskBadge = document.getElementById('security-risk-badge');

    if (riskBadge) {
      riskBadge.textContent = `RISK SCORE: ${weightedRiskScore}/100 (${riskLevel})`;
      riskBadge.className = `badge ${riskLevel === 'CRITICAL' ? 'badge-critical' : (riskLevel === 'HIGH' ? 'badge-high' : (riskLevel === 'MEDIUM' ? 'badge-medium' : 'badge-low'))}`;
    }

    if (!tableBody || !checks) return;

    tableBody.innerHTML = checks.map(c => {
      const statusBadge = c.passed
        ? `<span class="badge" style="background:#d1fae5; color:#065f46; font-weight:800;">✓ VERIFIED</span>`
        : `<span class="badge" style="background:#fee2e2; color:#991b1b; font-weight:800;">✗ MISMATCH ${c.penalty ? `(+${c.penalty} Risk)` : ''}</span>`;

      return `
        <tr>
          <td><strong>${c.check}</strong></td>
          <td><code style="color:#059669;">${c.baseline}</code></td>
          <td><code style="color:${c.passed ? '#334155' : '#dc2626'}; font-weight:${c.passed ? 'normal' : '700'};">${c.incoming}</code></td>
          <td>${statusBadge}</td>
        </tr>
      `;
    }).join('');
  }
});
