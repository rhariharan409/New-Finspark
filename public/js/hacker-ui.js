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

  // =========================================================================
  // CARD-NOT-PRESENT (CNP) FRAUD ATTACK SIMULATION LAB CONTROLLER
  // =========================================================================

  const tabCnp = document.getElementById('tab-cnp-attack');
  const tabAto = document.getElementById('tab-ato-attack');
  const cnpLabSection = document.getElementById('cnp-attack-lab');

  if (tabCnp && tabAto) {
    tabCnp.addEventListener('click', () => {
      if (cnpLabSection) cnpLabSection.style.display = 'block';
      if (verificationCard) verificationCard.style.display = 'none';
      if (simulationCard) simulationCard.style.display = 'none';
      tabCnp.style.background = '#0f172a';
      tabCnp.style.color = '#38bdf8';
      tabAto.style.background = '#f1f5f9';
      tabAto.style.color = '#475569';
    });

    tabAto.addEventListener('click', () => {
      if (cnpLabSection) cnpLabSection.style.display = 'none';
      if (verificationCard && !activeVerifiedSessionId) verificationCard.style.display = 'block';
      if (simulationCard && activeVerifiedSessionId) simulationCard.style.display = 'block';
      tabAto.style.background = '#0f172a';
      tabAto.style.color = '#38bdf8';
      tabCnp.style.background = '#f1f5f9';
      tabCnp.style.color = '#475569';
    });
  }

  // Preset Configurations
  const cnpPresets = {
    PRESET_1: {
      cardProfileType: 'SYNTHETIC_STOLEN',
      amount: 85000,
      merchant: 'Unknown Electronics Marketplace',
      category: 'ELECTRONICS',
      channel: 'ONLINE',
      shipping: 'HIGH_RISK_MISMATCH',
      velocity: '3 attempts in 10 mins',
      envMode: 'REALISTIC',
      attackerEnv: {
        deviceFingerprint: 'FP-SIMULATED-ATTACKER',
        browserName: 'Chrome 126',
        operatingSystem: 'Linux Ubuntu',
        ipAddress: '192.168.1.50 (VPN)',
        location: 'Mumbai, IN'
      }
    },
    PRESET_2: {
      cardProfileType: 'SYNTHETIC_STOLEN',
      amount: 145000,
      merchant: 'Luxury Global Travel & Aviation',
      category: 'TRAVEL',
      channel: 'WEB_CHECKOUT',
      shipping: 'HIGH_RISK_MISMATCH',
      velocity: '5 attempts in 5 mins',
      envMode: 'REALISTIC',
      attackerEnv: {
        deviceFingerprint: 'FP-ATO-CRITICAL',
        browserName: 'Firefox 125',
        operatingSystem: 'Android 14',
        ipAddress: '185.220.101.5 (Tor Exit)',
        location: 'London, UK'
      }
    },
    PRESET_3: {
      cardProfileType: 'SYNTHETIC_STOLEN',
      amount: 25000,
      merchant: 'Digital Gaming Gift Voucher Code Store',
      category: 'DIGITAL_GOODS',
      channel: 'ONLINE',
      shipping: 'DIFFERENT',
      velocity: '12 attempts in 2 mins',
      envMode: 'REALISTIC',
      attackerEnv: {
        deviceFingerprint: 'FP-BOT-STUFFING-01',
        browserName: 'HeadlessChrome',
        operatingSystem: 'Linux',
        ipAddress: '103.21.244.0 (Proxy)',
        location: 'Delhi, IN'
      }
    },
    PRESET_4: {
      cardProfileType: 'SYNTHETIC_STOLEN',
      amount: 4900,
      merchant: 'Micro Subscription Streaming Service',
      category: 'SUBSCRIPTION',
      channel: 'IN_APP',
      shipping: 'MATCHED',
      velocity: '1 attempt every 2 hours',
      envMode: 'REALISTIC',
      attackerEnv: {
        deviceFingerprint: 'FP-SLOW-LOW-88',
        browserName: 'Safari 17',
        operatingSystem: 'macOS Sonoma',
        ipAddress: '45.12.18.99',
        location: 'Singapore'
      }
    },
    PRESET_5: {
      cardProfileType: 'SYNTHETIC_STOLEN',
      amount: 98000,
      merchant: 'High Value Crypto Tech Hardware Store',
      category: 'ELECTRONICS',
      channel: 'ONLINE',
      shipping: 'HIGH_RISK_MISMATCH',
      velocity: '2 attempts in 1 min',
      envMode: 'REALISTIC',
      attackerEnv: {
        deviceFingerprint: 'FP-IMPOSSIBLE-TRAVEL',
        browserName: 'Chrome Mobile',
        operatingSystem: 'iOS 17',
        ipAddress: '198.51.100.44',
        location: 'Frankfurt, DE'
      }
    }
  };

  // Preset Selector Listener
  const presetButtons = document.querySelectorAll('.cnp-preset-btn');
  presetButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      presetButtons.forEach(b => {
        b.style.background = '#1e293b';
        b.style.color = '#cbd5e1';
        b.style.border = '1px solid #334155';
      });
      btn.style.background = '#2563eb';
      btn.style.color = '#ffffff';
      btn.style.border = 'none';

      const key = btn.getAttribute('data-preset');
      const data = cnpPresets[key];
      if (!data) return;

      const amtInput = document.getElementById('cnp-input-amount');
      const merchInput = document.getElementById('cnp-input-merchant');
      const catInput = document.getElementById('cnp-input-category');
      const chanInput = document.getElementById('cnp-input-channel');
      const shipInput = document.getElementById('cnp-input-shipping');
      const velInput = document.getElementById('cnp-input-velocity');

      if (amtInput) amtInput.value = data.amount;
      if (merchInput) merchInput.value = data.merchant;
      if (catInput) catInput.value = data.category;
      if (chanInput) chanInput.value = data.channel;
      if (shipInput) shipInput.value = data.shipping;
      if (velInput) velInput.value = data.velocity;

      // Update DNA profile preview
      const dnaAmt = document.getElementById('dna-attack-amount');
      const dnaMerch = document.getElementById('dna-attack-merchant');
      const dnaLoc = document.getElementById('dna-attack-location');
      const dnaDev = document.getElementById('dna-attack-device');

      if (dnaAmt) dnaAmt.textContent = `₹${data.amount.toLocaleString()}`;
      if (dnaMerch) dnaMerch.textContent = data.merchant;
      if (dnaLoc) dnaLoc.textContent = data.attackerEnv.location;
      if (dnaDev) dnaDev.textContent = `${data.attackerEnv.browserName} on ${data.attackerEnv.operatingSystem}`;
    });
  });

  // Launch CNP Attack Simulation Handler
  const cnpLaunchBtn = document.getElementById('cnp-launch-btn');
  const cnpResultsContainer = document.getElementById('cnp-results-container');
  const cnpStatusChecklist = document.getElementById('cnp-status-checklist');
  const cnpReasonsList = document.getElementById('cnp-reasons-list');

  if (cnpLaunchBtn) {
    cnpLaunchBtn.addEventListener('click', async () => {
      cnpLaunchBtn.disabled = true;
      cnpLaunchBtn.textContent = '⏳ EXECUTING ATTACK CHAIN SIMULATION...';

      // Reset Timeline Stepper
      const steps = document.querySelectorAll('#attack-timeline-stepper .timeline-step');
      steps.forEach((s, idx) => {
        if (idx === 0) {
          s.style.borderColor = '#38bdf8';
          s.querySelector('div:first-child').style.color = '#38bdf8';
        } else {
          s.style.borderColor = '#334155';
          s.querySelector('div:first-child').style.color = '#64748b';
        }
      });

      // Animate Timeline Steps
      for (let i = 1; i < steps.length; i++) {
        await new Promise(r => setTimeout(r, 200));
        steps[i].style.borderColor = '#38bdf8';
        steps[i].querySelector('div:first-child').style.color = '#38bdf8';
      }

      // Collect Payload
      const amtVal = parseFloat(document.getElementById('cnp-input-amount')?.value) || 85000;
      const merchVal = document.getElementById('cnp-input-merchant')?.value || 'Unknown Electronics Marketplace';
      const catVal = document.getElementById('cnp-input-category')?.value || 'ELECTRONICS';
      const chanVal = document.getElementById('cnp-input-channel')?.value || 'ONLINE';
      const shipVal = document.getElementById('cnp-input-shipping')?.value || 'HIGH_RISK_MISMATCH';
      const velVal = document.getElementById('cnp-input-velocity')?.value || '3 attempts in 10 mins';

      const payload = {
        simulationMode: 'CNP_ATTACK',
        scenario: 'ACCOUNT_TAKEOVER_CNP',
        sessionId: activeVerifiedSessionId || 'SES-9C213624',
        cardToken: 'DEMO-TOKEN-4521',
        cardNetwork: 'VISA',
        lastFourDigits: '4521',
        cardholderName: 'HARI DEMO',
        cardProfileType: 'SYNTHETIC_STOLEN',
        transactionAmount: amtVal,
        merchantName: merchVal,
        merchantCategory: catVal,
        channel: chanVal,
        shippingBillingRelation: shipVal,
        velocity: velVal,
        failedAttempts: 2,
        clientEnv: {
          deviceFingerprint: 'FP-SIMULATED-ATTACKER',
          browserName: 'Chrome 126',
          operatingSystem: 'Linux Ubuntu',
          ipAddress: '192.168.1.50',
          location: 'Mumbai, IN'
        }
      };

      try {
        const res = await fetch('/api/transactions/simulate-cnp-attack', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });

        const data = await res.json();
        cnpLaunchBtn.disabled = false;
        cnpLaunchBtn.textContent = '🚀 LAUNCH CNP ATTACK SIMULATION';

        if (!res.ok || !data.success) {
          alert(data.message || 'Error executing CNP simulation.');
          return;
        }

        // Render Status Checklist & Breakdown
        if (cnpResultsContainer) cnpResultsContainer.style.display = 'block';

        if (cnpStatusChecklist) {
          cnpStatusChecklist.innerHTML = `
            <div>[<span style="color:#34d399;">✓</span>] Synthetic card profile loaded (VISA **** 4521)</div>
            <div>[<span style="color:#34d399;">✓</span>] CNP Channel identified (${data.cnpDetails?.channel || 'ONLINE'})</div>
            <div>[<span style="color:#34d399;">✓</span>] Target session verified (${data.sessionId})</div>
            <div>[<span style="color:#f43f5e;">!</span>] Device fingerprint mismatch (+40 Risk)</div>
            <div>[<span style="color:#f43f5e;">!</span>] Browser environment mismatch (+20 Risk)</div>
            <div>[<span style="color:#fbbf24;">!</span>] Suspicious network IP anomaly (+15 Risk)</div>
            <div>[<span style="color:#f43f5e;">!</span>] Location deviation detected (+20 Risk)</div>
            <div>[<span style="color:#f43f5e;">!</span>] Transaction amount anomaly (+25 Risk)</div>
            <div>[<span style="color:#f43f5e;">!</span>] Behavioral Transaction DNA mismatch (+25 Risk)</div>
            <div>[<span style="color:#f43f5e; font-weight:800;">BLOCKED</span>] Transaction blocked by FINSPARK Risk Engine</div>
          `;
        }

        // Update Breakdown Scores
        const b = data.riskBreakdown || {};
        if (document.getElementById('score-device')) document.getElementById('score-device').textContent = `+${b.deviceRisk || 40}`;
        if (document.getElementById('score-browser')) document.getElementById('score-browser').textContent = `+${b.browserRisk || 20}`;
        if (document.getElementById('score-network')) document.getElementById('score-network').textContent = `+${b.networkRisk || 15}`;
        if (document.getElementById('score-location')) document.getElementById('score-location').textContent = `+${b.locationRisk || 20}`;
        if (document.getElementById('score-amount')) document.getElementById('score-amount').textContent = `+${b.transactionAmountRisk || 25}`;
        if (document.getElementById('score-merchant')) document.getElementById('score-merchant').textContent = `+${b.merchantRisk || 10}`;
        if (document.getElementById('score-dna')) document.getElementById('score-dna').textContent = `+${b.behavioralDnaRisk || 25}`;

        // Update Final Result Badge & Reasons
        const totalBadge = document.getElementById('cnp-total-risk-badge');
        if (totalBadge) {
          totalBadge.textContent = `TOTAL RISK: ${b.totalRiskScore || 95}/100 (${b.riskLevel || 'CRITICAL'})`;
        }

        if (cnpReasonsList && data.detectionReasons) {
          cnpReasonsList.innerHTML = data.detectionReasons.map(r => `<li>${r}</li>`).join('');
        }

        // Smooth scroll to results
        cnpResultsContainer.scrollIntoView({ behavior: 'smooth' });

      } catch (err) {
        cnpLaunchBtn.disabled = false;
        cnpLaunchBtn.textContent = '🚀 LAUNCH CNP ATTACK SIMULATION';
        alert('Network error launching CNP simulation.');
      }
    });
  }
});
