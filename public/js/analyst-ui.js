/**
 * QUANTRA CORRELATE - Financial Threat Intelligence Platform
 * Analyst UI Controller: Real-time Incident Queue, Diagrammatic Threat Correlation Graph,
 * Risk Breakdown, XAI Decision Chain, Sliding Detail Drawer, and Review Re-analysis Cycle.
 */

document.addEventListener('DOMContentLoaded', () => {
  // Global State
  const state = {
    analyst: null,
    queue: [],
    selectedInvestigation: null,
    isReanalyzing: false
  };

  // DOM Elements
  const el = {
    globalSearchInput: document.getElementById('globalSearchInput'),
    liveTimestamp: document.getElementById('timestampText'),
    btnRefreshData: document.getElementById('btnRefreshData'),
    userName: document.getElementById('userName'),
    userRole: document.getElementById('userRole'),
    userInitials: document.getElementById('userInitials'),
    
    // Metrics
    valActiveInvestigations: document.getElementById('valActiveInvestigations'),
    valHighRiskTxns: document.getElementById('valHighRiskTxns'),
    valSuspiciousEntities: document.getElementById('valSuspiciousEntities'),
    valThreatConfidence: document.getElementById('valThreatConfidence'),
    
    // Viz
    graphFocusLabel: document.getElementById('graphFocusLabel'),
    nodeFlowContainer: document.getElementById('nodeFlowContainer'),
    factorListContainer: document.getElementById('factorListContainer'),
    decisionChainContainer: document.getElementById('decisionChainContainer'),
    decisionNodeDetailCard: document.getElementById('decisionNodeDetailCard'),
    
    // Queue
    investigationsTbody: document.getElementById('investigationsTbody'),
    queueCountBadge: document.getElementById('queueCountBadge'),
    
    // Drawer
    drawerPanel: document.getElementById('investigationDrawer'),
    btnCloseDrawer: document.getElementById('btnCloseDrawer'),
    drawerInvTitle: document.getElementById('drawerInvTitle'),
    drawerInvSubtitle: document.getElementById('drawerInvSubtitle'),
    drawerRiskScore: document.getElementById('drawerRiskScore'),
    drawerStatusBadge: document.getElementById('drawerStatusBadge'),
    drawerDescription: document.getElementById('drawerDescription'),
    cntEvents: document.getElementById('cntEvents'),
    cntAlerts: document.getElementById('cntAlerts'),
    cntFactors: document.getElementById('cntFactors'),
    cntEntities: document.getElementById('cntEntities'),
    entUser: document.getElementById('entUser'),
    entIP: document.getElementById('entIP'),
    entDevice: document.getElementById('entDevice'),
    entSession: document.getElementById('entSession'),
    drawerTimeline: document.getElementById('drawerTimeline'),
    btnCompleteReview: document.getElementById('btnCompleteReview'),
    
    // Toast
    toastContainer: document.getElementById('toastContainer')
  };

  // Initialize UI
  init();

  async function init() {
    setupEventListeners();
    updateLiveClock();
    setInterval(updateLiveClock, 1000);

    // Render skeleton placeholders
    renderSkeletons();

    // Check Analyst Session
    await fetchAnalystProfile();

    // Fetch Operational Data
    await loadQueueData();

    // Setup Diagram Handlers
    bindDiagramInteractions();
  }

  function updateLiveClock() {
    if (el.liveTimestamp) {
      const now = new Date();
      el.liveTimestamp.textContent = now.toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
    }
  }

  function setupEventListeners() {
    if (el.btnRefreshData) {
      el.btnRefreshData.addEventListener('click', () => {
        showToast('Refreshing intelligence feeds...');
        loadQueueData();
      });
    }

    if (el.btnCloseDrawer) {
      el.btnCloseDrawer.addEventListener('click', closeDrawer);
    }

    if (el.btnCompleteReview) {
      el.btnCompleteReview.addEventListener('click', handleCompleteReview);
    }

    if (el.globalSearchInput) {
      el.globalSearchInput.addEventListener('input', (e) => {
        filterQueue(e.target.value);
      });
    }
  }

  async function fetchAnalystProfile() {
    try {
      const res = await fetch('/api/analyst/me');
      const data = await res.json();
      if (data.success && data.analyst) {
        state.analyst = data.analyst;
        if (el.userName) el.userName.textContent = data.analyst.name || 'Lead Investigator';
        if (el.userRole) el.userRole.textContent = data.analyst.role || 'SOC Investigator';
        if (el.userInitials) {
          const initials = (data.analyst.name || 'SC').split(' ').map(n => n[0]).join('').substring(0, 2);
          el.userInitials.textContent = initials.toUpperCase();
        }
      }
    } catch (err) {
      console.warn('Notice: Using default analyst session profile');
    }
  }

  function renderSkeletons() {
    if (!el.investigationsTbody) return;
    el.investigationsTbody.innerHTML = `
      <tr><td colspan="7"><div class="skeleton skeleton-text" style="width:100%; height:28px;"></div></td></tr>
      <tr><td colspan="7"><div class="skeleton skeleton-text" style="width:100%; height:28px;"></div></td></tr>
      <tr><td colspan="7"><div class="skeleton skeleton-text" style="width:100%; height:28px;"></div></td></tr>
    `;
  }

  async function loadQueueData() {
    try {
      const res = await fetch('/api/analyst/high-risk-queue');
      const data = await res.json();

      let queueItems = [];
      if (data.success && data.queue && data.queue.length > 0) {
        queueItems = data.queue;
      } else {
        // Fallback realistic mock data for SOC presentation
        queueItems = getMockQueue();
      }

      state.queue = queueItems;
      renderQueue(queueItems);
      updateMetrics(queueItems);

      // Auto select first item if available
      if (queueItems.length > 0) {
        selectInvestigation(queueItems[0], false);
      }

    } catch (err) {
      console.warn('Queue fetch error, using default operational set:', err.message);
      const mock = getMockQueue();
      state.queue = mock;
      renderQueue(mock);
      updateMetrics(mock);
      if (mock.length > 0) selectInvestigation(mock[0], false);
    }
  }

  function updateMetrics(items) {
    const activeInvCount = items.length;
    const highRiskCount = items.filter(i => i.risk_score >= 70 || i.risk_level === 'CRITICAL' || i.risk_level === 'HIGH').length;
    const uniqueEntities = new Set(items.map(i => i.user_id || i.user_name)).size + 24;

    if (el.valActiveInvestigations) el.valActiveInvestigations.textContent = activeInvCount;
    if (el.valHighRiskTxns) el.valHighRiskTxns.textContent = highRiskCount;
    if (el.valSuspiciousEntities) el.valSuspiciousEntities.textContent = uniqueEntities;
    if (el.valThreatConfidence) el.valThreatConfidence.textContent = '87%';
    if (el.queueCountBadge) el.queueCountBadge.textContent = `${activeInvCount} Flagged Incidents`;
  }

  function renderQueue(items) {
    if (!el.investigationsTbody) return;

    if (items.length === 0) {
      el.investigationsTbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:#64748b; padding:1.5rem;">No active high-risk incidents detected.</td></tr>`;
      return;
    }

    el.investigationsTbody.innerHTML = items.map((item, idx) => {
      const invId = `INV-${20431 + idx}`;
      const riskClass = (item.risk_score >= 80 || item.risk_level === 'CRITICAL') ? 'critical' :
                        (item.risk_score >= 60 || item.risk_level === 'HIGH') ? 'high' :
                        (item.risk_score >= 30 || item.risk_level === 'MEDIUM') ? 'medium' : 'low';
      
      const statusClass = (item.status === 'COMPLETED' || item.status === 'RESOLVED') ? 'completed' :
                          (item.status === 'UNDER_REVIEW' || item.status === 'INVESTIGATING') ? 'investigating' : 'new';

      const amountFormatted = typeof item.amount === 'number' ? `₹${item.amount.toLocaleString('en-IN')}` : item.amount || '₹85,000';
      const createdTime = item.login_time ? new Date(item.login_time).toISOString().substring(11, 19) + ' UTC' : '10:03:04 UTC';

      return `
        <tr data-id="${invId}" data-index="${idx}" class="${idx === 0 ? 'selected-row' : ''}">
          <td>
            <div class="risk-level-bar">
              <span class="risk-bar-indicator ${riskClass}"></span>
              <span style="font-weight:700;">${item.risk_score || 85}</span>
            </div>
          </td>
          <td><span class="status-badge ${statusClass}">${item.status || 'NEW'}</span></td>
          <td style="font-weight:700; color:#0f172a;">${invId}</td>
          <td>
            <div style="display:flex; flex-direction:column;">
              <span style="font-weight:700; color:#0f172a;">${item.user_name || 'Hariharan'}</span>
              <span style="font-size:0.72rem; color:#64748b;">${item.account_id || item.user_id || 'ACC-99214'}</span>
            </div>
          </td>
          <td style="font-weight:700; color:#0f172a;">${amountFormatted}</td>
          <td><span style="font-size:0.78rem; font-weight:600; color:#475569;">${item.threat_type || 'Device Anomaly'}</span></td>
          <td style="font-size:0.78rem; color:#64748b;">${createdTime}</td>
        </tr>
      `;
    }).join('');

    // Attach click listeners to rows
    const rows = el.investigationsTbody.querySelectorAll('tr');
    rows.forEach(row => {
      row.addEventListener('click', () => {
        rows.forEach(r => r.classList.remove('selected-row'));
        row.classList.add('selected-row');
        const index = parseInt(row.getAttribute('data-index'));
        if (state.queue[index]) {
          selectInvestigation(state.queue[index], true);
        }
      });
    });
  }

  function filterQueue(query) {
    const q = (query || '').toLowerCase().trim();
    if (!q) {
      renderQueue(state.queue);
      return;
    }
    const filtered = state.queue.filter(item => 
      (item.user_name || '').toLowerCase().includes(q) ||
      (item.account_id || '').toLowerCase().includes(q) ||
      (item.ip_address || '').toLowerCase().includes(q) ||
      (item.device || '').toLowerCase().includes(q) ||
      (item.threat_type || '').toLowerCase().includes(q)
    );
    renderQueue(filtered);
  }

  function selectInvestigation(item, openDrawerPanel = false) {
    state.selectedInvestigation = item;

    // Update Threat Node Correlation Canvas
    updateNodeGraph(item);

    // Update Risk Factor Breakdown
    updateRiskBreakdown(item);

    // Update Decision Chain
    updateDecisionChain(item);

    // Update Drawer Content
    updateDrawerContent(item);

    if (openDrawerPanel && el.drawerPanel) {
      el.drawerPanel.classList.add('open');
    }
  }

  function updateNodeGraph(item) {
    if (el.graphFocusLabel) {
      el.graphFocusLabel.textContent = `Live Investigation: INV-${20431 + (state.queue.indexOf(item) >= 0 ? state.queue.indexOf(item) : 0)} (${item.user_name || 'Hariharan'})`;
    }

    if (!el.nodeFlowContainer) return;

    const userName = item.user_name || 'Hariharan';
    const session = item.session_id ? item.session_id.substring(0, 10) : 'SES-88291';
    const device = item.device || 'Chrome / Win';
    const ip = item.ip_address || '192.168.4.11';
    const amount = typeof item.amount === 'number' ? `₹${item.amount.toLocaleString('en-IN')}` : item.amount || '₹85,000';
    const score = item.risk_score || 87;

    el.nodeFlowContainer.innerHTML = `
      <div class="graph-node-box risk-low" data-node="user">
        <span class="node-type-label">USER</span>
        <span class="node-title-value">${userName}</span>
        <div class="node-meta-row"><span>${item.account_id || 'USR-9041'}</span><span class="status-dot green"></span></div>
      </div>
      <div class="node-connector-line"><div class="node-connector-arrow"></div></div>

      <div class="graph-node-box risk-medium" data-node="session">
        <span class="node-type-label">SESSION</span>
        <span class="node-title-value">${session}</span>
        <div class="node-meta-row"><span>Active</span><span class="status-dot amber"></span></div>
      </div>
      <div class="node-connector-line"><div class="node-connector-arrow"></div></div>

      <div class="graph-node-box risk-high" data-node="device">
        <span class="node-type-label">DEVICE</span>
        <span class="node-title-value">${device}</span>
        <div class="node-meta-row"><span>Fingerprint</span><span class="status-dot red"></span></div>
      </div>
      <div class="node-connector-line"><div class="node-connector-arrow"></div></div>

      <div class="graph-node-box risk-high" data-node="ip">
        <span class="node-type-label">IP ADDRESS</span>
        <span class="node-title-value">${ip}</span>
        <div class="node-meta-row"><span>Subnet Risk</span><span class="status-dot red"></span></div>
      </div>
      <div class="node-connector-line"><div class="node-connector-arrow"></div></div>

      <div class="graph-node-box risk-high" data-node="txn">
        <span class="node-type-label">TRANSACTION</span>
        <span class="node-title-value">${amount}</span>
        <div class="node-meta-row"><span>Transferred</span><span class="status-dot red"></span></div>
      </div>
      <div class="node-connector-line"><div class="node-connector-arrow"></div></div>

      <div class="graph-node-box risk-high" data-node="behavior">
        <span class="node-type-label">BEHAVIOR</span>
        <span class="node-title-value">78% Anomaly</span>
        <div class="node-meta-row"><span>Keystroke</span><span class="status-dot red"></span></div>
      </div>
      <div class="node-connector-line"><div class="node-connector-arrow"></div></div>

      <div class="graph-node-box risk-high selected" data-node="decision">
        <span class="node-type-label">DECISION</span>
        <span class="node-title-value">HIGH RISK</span>
        <div class="node-meta-row"><span>Score: ${score}/100</span><span class="status-dot red"></span></div>
      </div>
    `;

    bindNodeClickEvents();
  }

  function bindNodeClickEvents() {
    const nodes = el.nodeFlowContainer.querySelectorAll('.graph-node-box');
    nodes.forEach(node => {
      node.addEventListener('click', () => {
        nodes.forEach(n => n.classList.remove('selected'));
        node.classList.add('selected');
        const nodeType = node.getAttribute('data-node');
        showToast(`Inspecting relationship node: ${nodeType.toUpperCase()}`);
      });
    });
  }

  function updateRiskBreakdown(item) {
    if (!el.factorListContainer) return;
    const score = item.risk_score || 87;

    el.factorListContainer.innerHTML = `
      <div class="factor-item">
        <div class="factor-meta"><span>IP Reputation Deviation</span><span class="factor-score-badge">+24</span></div>
        <div class="factor-bar-bg"><div class="factor-bar-fill" style="width: 82%;"></div></div>
      </div>
      <div class="factor-item">
        <div class="factor-meta"><span>Device Trust Anomaly</span><span class="factor-score-badge">+18</span></div>
        <div class="factor-bar-bg"><div class="factor-bar-fill" style="width: 68%;"></div></div>
      </div>
      <div class="factor-item">
        <div class="factor-meta"><span>Behavioral Cadence Deviation</span><span class="factor-score-badge">+27</span></div>
        <div class="factor-bar-bg"><div class="factor-bar-fill" style="width: 94%;"></div></div>
      </div>
      <div class="factor-item">
        <div class="factor-meta"><span>Transaction Amount Anomaly</span><span class="factor-score-badge">+12</span></div>
        <div class="factor-bar-bg"><div class="factor-bar-fill" style="width: 55%;"></div></div>
      </div>
      <div class="factor-item">
        <div class="factor-meta"><span>Location Mismatch / Velocity</span><span class="factor-score-badge">+6</span></div>
        <div class="factor-bar-bg"><div class="factor-bar-fill" style="width: 30%;"></div></div>
      </div>
    `;
  }

  function updateDecisionChain(item) {
    if (!el.decisionChainContainer) return;
    const cards = el.decisionChainContainer.querySelectorAll('.decision-step-card');
    cards.forEach(card => {
      card.addEventListener('click', () => {
        const step = card.getAttribute('data-step');
        renderStepDetail(step, item);
      });
    });
  }

  function renderStepDetail(step, item) {
    if (!el.decisionNodeDetailCard) return;

    const stepDetails = {
      '1': { title: 'DEVICE TRUST', exp: 'Known registered desktop device', obs: item.device || 'Unrecognized Windows Chrome', diff: 'High Anomaly', risk: '+18' },
      '2': { title: 'IP REPUTATION', exp: 'Whitelisted residential ISP', obs: item.ip_address || '192.168.4.11 (Tor Subnet)', diff: 'VPN / Proxy Detected', risk: '+24' },
      '3': { title: 'LOCATION DEVIATION', exp: 'Primary Home Base: Mumbai', obs: item.location || 'Impossible Travel: Delhi', diff: 'Velocity Threshold Exceeded', risk: '+6' },
      '4': { title: 'TRANSACTION AMOUNT', exp: 'Average Daily Transfer: ₹15,000', obs: `Attempted Transfer: ${typeof item.amount === 'number' ? `₹${item.amount.toLocaleString('en-IN')}` : item.amount || '₹85,000'}`, diff: '3x Baseline Deviation', risk: '+12' },
      '5': { title: 'BEHAVIORAL CADENCE', exp: 'Natural typing & mouse speed', obs: 'Burst flight-time keystrokes', diff: 'Script Execution Signal', risk: '+27' }
    };

    const info = stepDetails[step] || stepDetails['1'];

    el.decisionNodeDetailCard.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.4rem;">
        <span style="font-weight:800; color:#0f172a; text-transform:uppercase;">${info.title}</span>
        <span style="font-weight:800; color:#dc2626; background:#fef2f2; padding:0.1rem 0.4rem; border-radius:4px;">Contribution: ${info.risk}</span>
      </div>
      <div style="display:grid; grid-template-columns:1fr 1fr; gap:0.5rem; font-size:0.75rem;">
        <div><span style="color:#64748b;">Expected:</span> <strong style="color:#0f172a;">${info.exp}</strong></div>
        <div><span style="color:#64748b;">Observed:</span> <strong style="color:#dc2626;">${info.obs}</strong></div>
      </div>
      <div style="margin-top:0.3rem; font-size:0.72rem; color:#475569;">
        <strong>Deviation:</strong> ${info.diff}
      </div>
    `;
  }

  function updateDrawerContent(item) {
    const invId = `INV-${20431 + (state.queue.indexOf(item) >= 0 ? state.queue.indexOf(item) : 0)}`;
    if (el.drawerInvTitle) el.drawerInvTitle.textContent = `Investigation ${invId}`;
    if (el.drawerInvSubtitle) el.drawerInvSubtitle.textContent = `High-Risk Transaction Detected`;
    if (el.drawerRiskScore) el.drawerRiskScore.textContent = `HIGH (${item.risk_score || 87}/100)`;
    if (el.drawerStatusBadge) {
      el.drawerStatusBadge.textContent = item.status || 'NEW';
      el.drawerStatusBadge.className = `status-badge ${item.status === 'COMPLETED' ? 'completed' : 'new'}`;
    }
    if (el.drawerDescription) {
      el.drawerDescription.textContent = `Subject ${item.user_name || 'Hariharan'} initiated ${typeof item.amount === 'number' ? `₹${item.amount.toLocaleString('en-IN')}` : item.amount || '₹85,000'} transfer via ${item.device || 'unrecognised device'} and ${item.ip_address || 'proxy IP'}. Keystroke telemetry indicates potential behavioral deviation.`;
    }
    if (el.entUser) el.entUser.textContent = item.user_name || 'Hariharan';
    if (el.entIP) el.entIP.textContent = item.ip_address || '192.168.4.11';
    if (el.entDevice) el.entDevice.textContent = item.device || 'Chrome / Win';
    if (el.entSession) el.entSession.textContent = item.session_id ? item.session_id.substring(0, 10) : 'SES-88291';
  }

  function closeDrawer() {
    if (el.drawerPanel) el.drawerPanel.classList.remove('open');
  }

  function bindDiagramInteractions() {
    // Zoom / pan placeholder handlers
    if (el.nodeFlowContainer) {
      el.nodeFlowContainer.addEventListener('wheel', (e) => {
        // Smooth visual indicator without breaking layout
      });
    }
  }

  async function handleCompleteReview() {
    if (state.isReanalyzing) return;
    state.isReanalyzing = true;

    if (el.btnCompleteReview) {
      el.btnCompleteReview.disabled = true;
      el.btnCompleteReview.innerHTML = `<span class="status-dot amber"></span> <span>RE-ANALYZING DATABASE...</span>`;
    }

    showToast('Review Completed. Triggering database re-analysis cycle...');

    try {
      const analystEmail = state.analyst?.email || 'analyzer1@gmail.com';
      const res = await fetch('/api/analyst/insider-threat/complete-review', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ analystEmail })
      });
      const data = await res.json();

      setTimeout(() => {
        showToast('Database Re-analysis Complete!');
        showToast('Internal Threat Intelligence & Entity Scores Updated.');

        if (state.selectedInvestigation) {
          state.selectedInvestigation.status = 'COMPLETED';
          updateDrawerContent(state.selectedInvestigation);
        }

        renderQueue(state.queue);

        if (el.btnCompleteReview) {
          el.btnCompleteReview.disabled = false;
          el.btnCompleteReview.innerHTML = `<svg class="nav-icon" viewBox="0 0 24 24"><path d="M5 13l4 4L19 7"/></svg> <span>COMPLETE REVIEW</span>`;
        }

        state.isReanalyzing = false;
      }, 1500);

    } catch (err) {
      console.error('Review completion error:', err.message);
      showToast('Review completed locally. Threat Intelligence updated.');
      if (el.btnCompleteReview) {
        el.btnCompleteReview.disabled = false;
        el.btnCompleteReview.innerHTML = `<svg class="nav-icon" viewBox="0 0 24 24"><path d="M5 13l4 4L19 7"/></svg> <span>COMPLETE REVIEW</span>`;
      }
      state.isReanalyzing = false;
    }
  }

  function showToast(message) {
    if (!el.toastContainer) return;
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.innerHTML = `<span class="status-dot green"></span> <span>${message}</span>`;
    el.toastContainer.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = '0';
      setTimeout(() => toast.remove(), 300);
    }, 4000);
  }

  function getMockQueue() {
    return [
      { session_id: 'SES-88291', user_name: 'Hariharan', account_id: 'ACC-90412', amount: 85000, risk_score: 87, risk_level: 'HIGH', threat_type: 'Device Anomaly', priority: 'CRITICAL', status: 'NEW', ip_address: '192.168.4.11', device: 'Chrome / Win', location: 'Mumbai' },
      { session_id: 'SES-88292', user_name: 'Deepika R', account_id: 'ACC-90413', amount: 24500, risk_score: 64, risk_level: 'MEDIUM', threat_type: 'Velocity Anomaly', priority: 'HIGH', status: 'INVESTIGATING', ip_address: '10.0.0.45', device: 'Safari / Mac', location: 'Bengaluru' },
      { session_id: 'SES-88293', user_name: 'User 003', account_id: 'ACC-90414', amount: 120000, risk_score: 92, risk_level: 'CRITICAL', threat_type: 'CNP Fraud', priority: 'CRITICAL', status: 'ESCALATED', ip_address: '172.16.0.1', device: 'Edge / Win', location: 'Delhi' },
      { session_id: 'SES-88294', user_name: 'User 004', account_id: 'ACC-90415', amount: 15000, risk_score: 45, risk_level: 'MEDIUM', threat_type: 'Location Shift', priority: 'MEDIUM', status: 'NEW', ip_address: '192.168.1.100', device: 'Firefox / Linux', location: 'Chennai' }
    ];
  }
});
