/**
 * FINSPARK - Professional Fraud Investigation Graph Controller
 * Interactive SVG Directed Money Flow Graph with Multi-Hop Traversal (Hops 1-4), Time Range Filtering, Zoom & Pan Viewport, Dragging, Risk Color Propagation, and Side Panels.
 */

let currentQuery = '';
let currentHops = 1;
let currentTimeRange = 'all';

let graphData = null; // Holds { nodes, edges, summary, target_user_id }
let nodePositions = {}; // Holds { userId: { x, y } }
let isDraggingNode = false;
let draggedNodeId = null;
let dragOffset = { x: 0, y: 0 };

// Viewport Zoom & Pan State
let transform = { scale: 1, translateX: 0, translateY: 0 };
let isPanningView = false;
let panStart = { x: 0, y: 0 };

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

  // Logout Button
  const logoutBtn = document.getElementById('analyst-logout-btn');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', async () => {
      if (autoRefreshTimer) clearInterval(autoRefreshTimer);
      try { await fetch('/api/analyst/logout', { method: 'POST' }); } catch (err) {}
      window.location.href = 'analyst-login.html';
    });
  }

  // Search Form
  const form = document.getElementById('analyst-search-form');
  const queryInput = document.getElementById('analyst-query-input');
  const alertEl = document.getElementById('analyst-search-alert');

  if (form) {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (alertEl) alertEl.style.display = 'none';

      const q = queryInput.value.trim();
      if (!q) return;

      currentQuery = q;
      const submitBtn = document.getElementById('analyst-search-btn');
      submitBtn.disabled = true;
      submitBtn.textContent = 'Investigating...';

      await executeFullInvestigation(currentQuery, true);
      submitBtn.disabled = false;
      submitBtn.textContent = 'Investigate Account';
    });
  }

  // Hop Depth Filter Buttons
  const hopBtns = document.querySelectorAll('.hop-filter-btn');
  hopBtns.forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.preventDefault();
      hopBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      currentHops = parseInt(btn.getAttribute('data-hop')) || 1;

      if (currentQuery) {
        await loadMoneyFlowGraph(currentQuery, currentHops, currentTimeRange);
      }
    });
  });

  // Time Range Filter Buttons
  const timeBtns = document.querySelectorAll('.time-filter-btn');
  timeBtns.forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.preventDefault();
      timeBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      currentTimeRange = btn.getAttribute('data-range') || 'all';

      if (currentQuery) {
        await loadMoneyFlowGraph(currentQuery, currentHops, currentTimeRange);
      }
    });
  });

  // Graph Zoom / Pan Control Buttons
  document.getElementById('btn-zoom-in')?.addEventListener('click', () => zoomViewport(1.2));
  document.getElementById('btn-zoom-out')?.addEventListener('click', () => zoomViewport(0.8));
  document.getElementById('btn-reset-view')?.addEventListener('click', () => resetViewport());
  document.getElementById('btn-auto-layout')?.addEventListener('click', () => {
    nodePositions = {};
    if (graphData) renderGraph(graphData);
  });

  // Side Panel Close Button
  document.getElementById('sp-close-btn')?.addEventListener('click', closeSidePanel);

  // Setup SVG Canvas Dragging / Pan Listeners
  setupGraphInteractions();

  // Periodic 6s silent refresh
  autoRefreshTimer = setInterval(async () => {
    if (currentQuery) {
      await executeFullInvestigation(currentQuery, false);
    }
  }, 6000);
}

/**
 * Main Account Investigation Orchestrator
 */
async function executeFullInvestigation(query, isManualSearch = false) {
  const alertEl = document.getElementById('analyst-search-alert');
  try {
    // 1. Fetch main account correlation intelligence
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

    renderInvestigationSummary(data);

    // 2. Load Multi-Hop Money Flow Graph
    await loadMoneyFlowGraph(query, currentHops, currentTimeRange, isManualSearch);

    const workspace = document.getElementById('investigation-workspace');
    if (workspace) workspace.style.display = 'block';

    if (isManualSearch && workspace) {
      window.scrollTo({ top: workspace.offsetTop - 80, behavior: 'smooth' });
    }

  } catch (err) {
    if (isManualSearch && alertEl) {
      alertEl.textContent = 'Network error executing account investigation.';
      alertEl.style.display = 'block';
    }
  }
}

/**
 * Renders Top Summary Cards & Session/Transaction Tables
 */
function renderInvestigationSummary(data) {
  const id = data.identity;
  const tx = data.transactions;
  const risk = data.risk_summary;

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

  // Session Analysis Table
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

  // Transaction Analysis Table
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

  // Behavioral Analysis
  const base = data.baseline_comparison;
  document.getElementById('beh-base-avg').textContent = `₹${(base.historical_baseline?.average_transaction_amount || 0).toFixed(2)}`;
  document.getElementById('beh-curr-dev').textContent = `${base.current_activity?.deviation_ratio || 1.0}x`;
  document.getElementById('beh-explanation').textContent = base.explanation;

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
}

/**
 * Loads Multi-Hop Money Flow Data from backend API
 */
async function loadMoneyFlowGraph(query, hops, range, isResetPositions = false) {
  try {
    const res = await fetch(`/api/analyst/money-flow?accountNumber=${encodeURIComponent(query)}&hops=${hops}&timeRange=${range}`);
    const data = await res.json();

    if (!res.ok || !data.found) {
      return;
    }

    graphData = data;
    if (isResetPositions) nodePositions = {};

    updateFlowSummaryMetrics(data);
    renderGraph(data);

  } catch (err) {
    console.error('Load money flow graph error:', err);
  }
}

/**
 * Updates Money Flow Summary Bar and Structuring Warning Box
 */
function updateFlowSummaryMetrics(data) {
  const sum = data.summary || {};
  document.getElementById('flow-period-val').textContent = `HOP ${data.max_hops} | ${data.time_range.toUpperCase()}`;
  document.getElementById('flow-total-txns').textContent = sum.total_transactions || 0;
  document.getElementById('flow-total-amount').textContent = `₹${(sum.total_amount_transferred || 0).toFixed(2)}`;
  document.getElementById('flow-senders-count').textContent = sum.unique_senders_count || 0;
  document.getElementById('flow-receivers-count').textContent = sum.unique_receivers_count || 0;

  const splitAlert = document.getElementById('flow-splitting-alert');
  const splitText = document.getElementById('flow-splitting-text');
  if (sum.split_pattern_detected) {
    if (splitText) splitText.textContent = sum.split_warning_text;
    if (splitAlert) splitAlert.style.display = 'block';
  } else {
    if (splitAlert) splitAlert.style.display = 'none';
  }
}

/**
 * SVG GRAPH ENGINE: Renders Interactive Directed Nodes & Edges
 */
function renderGraph(data) {
  const nodesLayer = document.getElementById('nodes-layer');
  const edgesLayer = document.getElementById('edges-layer');
  if (!nodesLayer || !edgesLayer) return;

  nodesLayer.innerHTML = '';
  edgesLayer.innerHTML = '';

  const nodes = data.nodes || [];
  const edges = data.edges || [];
  const targetId = data.target_user_id;

  // Auto-calculate node positions if not dragged
  const svgEl = document.getElementById('graph-svg');
  const width = svgEl.clientWidth || 900;
  const height = svgEl.clientHeight || 520;

  const centerX = width / 2;
  const centerY = height / 2;

  // Position target user in center
  if (!nodePositions[targetId]) {
    nodePositions[targetId] = { x: centerX, y: centerY };
  }

  // Partition other nodes into incoming (senders) & outgoing (receivers)
  const incomingNodeIds = [];
  const outgoingNodeIds = [];
  const otherNodeIds = [];

  edges.forEach(e => {
    if (e.target === targetId && !incomingNodeIds.includes(e.source)) incomingNodeIds.push(e.source);
    if (e.source === targetId && !outgoingNodeIds.includes(e.target)) outgoingNodeIds.push(e.target);
  });

  nodes.forEach(n => {
    if (n.id !== targetId && !incomingNodeIds.includes(n.id) && !outgoingNodeIds.includes(n.id)) {
      otherNodeIds.push(n.id);
    }
  });

  // Calculate layout coordinates for incoming nodes (top semicircle)
  incomingNodeIds.forEach((id, idx) => {
    if (!nodePositions[id]) {
      const step = Math.PI / (incomingNodeIds.length + 1);
      const angle = Math.PI + step * (idx + 1);
      nodePositions[id] = {
        x: centerX + 260 * Math.cos(angle),
        y: centerY + 180 * Math.sin(angle)
      };
    }
  });

  // Calculate layout coordinates for outgoing nodes (bottom semicircle)
  outgoingNodeIds.forEach((id, idx) => {
    if (!nodePositions[id]) {
      const step = Math.PI / (outgoingNodeIds.length + 1);
      const angle = step * (idx + 1);
      nodePositions[id] = {
        x: centerX + 260 * Math.cos(angle),
        y: centerY + 180 * Math.sin(angle)
      };
    }
  });

  // Multi-hop secondary nodes (outer perimeter)
  otherNodeIds.forEach((id, idx) => {
    if (!nodePositions[id]) {
      const step = (2 * Math.PI) / (otherNodeIds.length || 1);
      const angle = step * idx;
      nodePositions[id] = {
        x: centerX + 360 * Math.cos(angle),
        y: centerY + 240 * Math.sin(angle)
      };
    }
  });

  // 1. Render Directed Edges
  edges.forEach(edge => {
    const srcPos = nodePositions[edge.source];
    const tgtPos = nodePositions[edge.target];
    if (!srcPos || !tgtPos) return;

    const riskColor = edge.highest_risk_level === 'CRITICAL' ? '#dc2626' : (edge.highest_risk_level === 'HIGH' ? '#ea580c' : (edge.highest_risk_level === 'MEDIUM' ? '#d97706' : '#059669'));

    const edgeG = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    edgeG.setAttribute('class', 'edge-group');
    edgeG.style.cursor = 'pointer';
    edgeG.onclick = (e) => {
      e.stopPropagation();
      openEdgeSidePanel(edge);
    };

    // Curved edge line
    const dx = tgtPos.x - srcPos.x;
    const dy = tgtPos.y - srcPos.y;
    const cx = (srcPos.x + tgtPos.x) / 2 - dy * 0.15;
    const cy = (srcPos.y + tgtPos.y) / 2 + dx * 0.15;

    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', `M ${srcPos.x} ${srcPos.y} Q ${cx} ${cy} ${tgtPos.x} ${tgtPos.y}`);
    path.setAttribute('fill', 'none');
    path.setAttribute('stroke', riskColor);
    path.setAttribute('stroke-width', edge.is_split_pattern ? '3.5' : '2');
    path.setAttribute('marker-end', `url(#arrow-${edge.highest_risk_level || 'LOW'})`);
    if (edge.is_split_pattern) path.setAttribute('stroke-dasharray', '6 3');
    path.setAttribute('class', 'edge-line');

    // Edge Label Container
    const textX = (srcPos.x + tgtPos.x) / 2;
    const textY = (srcPos.y + tgtPos.y) / 2 - 8;

    const labelG = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    
    const rect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
    rect.setAttribute('x', textX - 45);
    rect.setAttribute('y', textY - 14);
    rect.setAttribute('width', '90');
    rect.setAttribute('height', '24');
    rect.setAttribute('rx', '4');
    rect.setAttribute('fill', '#ffffff');
    rect.setAttribute('stroke', riskColor);
    rect.setAttribute('stroke-width', '1');

    const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    text.setAttribute('x', textX);
    text.setAttribute('y', textY + 2);
    text.setAttribute('text-anchor', 'middle');
    text.setAttribute('fill', '#0f172a');
    text.setAttribute('font-size', '10px');
    text.setAttribute('font-weight', '700');
    text.textContent = `₹${edge.total_amount.toFixed(0)} (${edge.transaction_count})`;

    labelG.appendChild(rect);
    labelG.appendChild(text);

    edgeG.appendChild(path);
    edgeG.appendChild(labelG);
    edgesLayer.appendChild(edgeG);
  });

  // 2. Render Nodes
  nodes.forEach(node => {
    const pos = nodePositions[node.id];
    if (!pos) return;

    const isTarget = node.is_target;
    const borderColor = isTarget ? '#2563eb' : (node.risk_level === 'CRITICAL' ? '#dc2626' : (node.risk_level === 'HIGH' ? '#ea580c' : (node.risk_level === 'MEDIUM' ? '#d97706' : '#059669')));
    const bgColor = isTarget ? '#eff6ff' : '#ffffff';
    const badgeColor = node.risk_level === 'CRITICAL' ? '#dc2626' : (node.risk_level === 'HIGH' ? '#ea580c' : (node.risk_level === 'MEDIUM' ? '#d97706' : '#059669'));

    const nodeG = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    nodeG.setAttribute('class', 'node-group');
    nodeG.setAttribute('transform', `translate(${pos.x - 75}, ${pos.y - 35})`);
    
    // Node Card Rect
    const rect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
    rect.setAttribute('width', '150');
    rect.setAttribute('height', '70');
    rect.setAttribute('rx', '8');
    rect.setAttribute('fill', bgColor);
    rect.setAttribute('stroke', borderColor);
    rect.setAttribute('stroke-width', isTarget ? '3' : '1.5');
    if (isTarget) rect.setAttribute('filter', 'drop-shadow(0 4px 6px rgba(37,99,235,0.25))');

    // Risk Badge Pill
    const badgeRect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
    badgeRect.setAttribute('x', '95');
    badgeRect.setAttribute('y', '6');
    badgeRect.setAttribute('width', '48');
    badgeRect.setAttribute('height', '14');
    badgeRect.setAttribute('rx', '3');
    badgeRect.setAttribute('fill', badgeColor);

    const badgeText = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    badgeText.setAttribute('x', '119');
    badgeText.setAttribute('y', '16');
    badgeText.setAttribute('text-anchor', 'middle');
    badgeText.setAttribute('fill', '#ffffff');
    badgeText.setAttribute('font-size', '8px');
    badgeText.setAttribute('font-weight', '700');
    badgeText.textContent = node.risk_level;

    // Node Title (User Name)
    const titleText = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    titleText.setAttribute('x', '10');
    titleText.setAttribute('y', '22');
    titleText.setAttribute('fill', '#0f172a');
    titleText.setAttribute('font-size', '11px');
    titleText.setAttribute('font-weight', '700');
    titleText.textContent = truncateString(node.full_name, 14);

    // Account ID
    const accText = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    accText.setAttribute('x', '10');
    accText.setAttribute('y', '36');
    accText.setAttribute('fill', '#2563eb');
    accText.setAttribute('font-size', '9px');
    accText.setAttribute('font-weight', '600');
    accText.textContent = node.account_id;

    // Stats Line: Sent / Recv
    const statsText = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    statsText.setAttribute('x', '10');
    statsText.setAttribute('y', '54');
    statsText.setAttribute('fill', '#475569');
    statsText.setAttribute('font-size', '9px');
    statsText.textContent = `Sent: ₹${node.total_sent} | Recv: ₹${node.total_received}`;

    nodeG.appendChild(rect);
    nodeG.appendChild(badgeRect);
    nodeG.appendChild(badgeText);
    nodeG.appendChild(titleText);
    nodeG.appendChild(accText);
    nodeG.appendChild(statsText);

    // Node Click Listener -> Open Node Side Panel
    nodeG.onclick = (e) => {
      e.stopPropagation();
      openNodeSidePanel(node);
    };

    // Node Drag Listeners
    nodeG.onmousedown = (e) => {
      e.stopPropagation();
      isDraggingNode = true;
      draggedNodeId = node.id;
      const pt = getSVGPoint(e);
      dragOffset = { x: pt.x - pos.x, y: pt.y - pos.y };
    };

    nodesLayer.appendChild(nodeG);
  });

  applyViewportTransform();
}

/**
 * Side Panel Renderer for Node Click
 */
function openNodeSidePanel(node) {
  const panel = document.getElementById('side-panel');
  const title = document.getElementById('sp-title');
  const body = document.getElementById('sp-body');
  if (!panel || !body) return;

  if (title) title.textContent = `User Node Details: ${node.full_name}`;

  const levelClass = node.risk_level === 'CRITICAL' ? 'badge-critical' : (node.risk_level === 'HIGH' ? 'badge-high' : (node.risk_level === 'MEDIUM' ? 'badge-medium' : 'badge-low'));

  body.innerHTML = `
    <!-- User Overview -->
    <div style="background: #f8fafc; padding: 1rem; border-radius: 6px; border: 1px solid #e2e8f0; margin-bottom: 1.25rem;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
        <strong style="font-size: 1.05rem; color: #0f172a;">${node.full_name}</strong>
        <span class="badge ${levelClass}">${node.risk_level} RISK</span>
      </div>
      <div style="font-size: 0.85rem; color: #475569;">
        <div><strong>Account ID:</strong> <span style="color: #2563eb;">${node.account_id}</span></div>
        <div><strong>Email:</strong> ${node.email}</div>
        <div><strong>Account Status:</strong> <span style="color: #059669; font-weight: 600;">${node.account_status.toUpperCase()}</span></div>
      </div>
    </div>

    <!-- Financial Statistics -->
    <h4 style="font-size: 0.9rem; color: #0f172a; margin-bottom: 0.5rem; border-bottom: 1px solid #e2e8f0; padding-bottom: 0.25rem;">Financial Activity</h4>
    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; margin-bottom: 1.25rem;">
      <div class="summary-box">
        <span style="font-size: 0.7rem; color: #64748b;">Total Amount Sent</span>
        <div style="font-weight: 700; color: #dc2626; font-size: 1.1rem; margin-top: 0.15rem;">₹${node.total_sent.toFixed(2)}</div>
      </div>
      <div class="summary-box">
        <span style="font-size: 0.7rem; color: #64748b;">Total Amount Received</span>
        <div style="font-weight: 700; color: #059669; font-size: 1.1rem; margin-top: 0.15rem;">₹${node.total_received.toFixed(2)}</div>
      </div>
      <div class="summary-box">
        <span style="font-size: 0.7rem; color: #64748b;">Total Transactions</span>
        <div style="font-weight: 700; color: #0f172a; font-size: 1.1rem; margin-top: 0.15rem;">${node.transaction_count}</div>
      </div>
      <div class="summary-box">
        <span style="font-size: 0.7rem; color: #64748b;">Active Sessions</span>
        <div style="font-weight: 700; color: #0f172a; font-size: 1.1rem; margin-top: 0.15rem;">${node.session_count}</div>
      </div>
    </div>

    <!-- Risk & Behavioral Baselines -->
    <h4 style="font-size: 0.9rem; color: #0f172a; margin-bottom: 0.5rem; border-bottom: 1px solid #e2e8f0; padding-bottom: 0.25rem;">Risk Assessment & Behavior</h4>
    <div style="font-size: 0.85rem; color: #334155; background: #f8fafc; padding: 0.85rem; border-radius: 6px; border: 1px solid #e2e8f0; margin-bottom: 1.25rem;">
      <div><strong>Risk Score:</strong> <span style="font-weight: 700; color: #dc2626;">${node.risk_score}/100</span></div>
      <div><strong>Latest Decision:</strong> <span class="badge ${levelClass}">${node.latest_decision}</span></div>
      <div style="margin-top: 0.35rem;"><strong>Baseline Average:</strong> ₹${node.baseline_avg.toFixed(2)}</div>
      <div><strong>Largest Transaction:</strong> ₹${node.largest_tx.toFixed(2)}</div>
    </div>

    <button type="button" class="btn btn-primary btn-full" onclick="investigateNodeUser('${node.account_id}')">
      Focus Investigation on ${node.full_name}
    </button>
  `;

  panel.classList.add('open');
}

/**
 * Side Panel Renderer for Edge Click
 */
function openEdgeSidePanel(edge) {
  const panel = document.getElementById('side-panel');
  const title = document.getElementById('sp-title');
  const body = document.getElementById('sp-body');
  if (!panel || !body) return;

  if (title) title.textContent = `Directed Flow: ${edge.source_name} ➔ ${edge.target_name}`;

  const levelClass = edge.highest_risk_level === 'CRITICAL' ? 'badge-critical' : (edge.highest_risk_level === 'HIGH' ? 'badge-high' : (edge.highest_risk_level === 'MEDIUM' ? 'badge-medium' : 'badge-low'));

  body.innerHTML = `
    <!-- Edge Summary -->
    <div style="background: #f8fafc; padding: 1rem; border-radius: 6px; border: 1px solid #e2e8f0; margin-bottom: 1.25rem;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
        <strong style="font-size: 1rem; color: #0f172a;">${edge.source_name} ➔ ${edge.target_name}</strong>
        <span class="badge ${levelClass}">${edge.highest_risk_level} RISK</span>
      </div>
      <div style="font-size: 0.85rem; color: #475569;">
        <div><strong>Total Money Transferred:</strong> <span style="color: #059669; font-weight: 700;">₹${edge.total_amount.toFixed(2)}</span></div>
        <div><strong>Transaction Count:</strong> ${edge.transaction_count}</div>
        <div><strong>Last Transfer Time:</strong> ${new Date(edge.last_timestamp).toLocaleString()}</div>
      </div>
    </div>

    ${edge.is_split_pattern ? `
      <div class="alert alert-warning" style="margin-bottom: 1.25rem;">
        <strong>⚠️ Structuring Warning:</strong> Multiple rapid transfers detected between these accounts.
      </div>
    ` : ''}

    <!-- Itemized Transactions Table -->
    <h4 style="font-size: 0.9rem; color: #0f172a; margin-bottom: 0.5rem; border-bottom: 1px solid #e2e8f0; padding-bottom: 0.25rem;">Itemized Transfers</h4>
    <div style="overflow-x: auto;">
      <table class="data-table" style="font-size: 0.8rem;">
        <thead>
          <tr>
            <th>Txn ID</th>
            <th>Amount</th>
            <th>Timestamp</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          ${edge.transactions.map(t => `
            <tr>
              <td><strong>${t.transaction_id}</strong></td>
              <td style="font-weight:700; color:#059669;">₹${parseFloat(t.amount).toFixed(2)}</td>
              <td>${new Date(t.transaction_timestamp || t.created_at).toLocaleTimeString()}</td>
              <td><span class="badge badge-low">${t.transaction_status || 'completed'}</span></td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
  `;

  panel.classList.add('open');
}

function closeSidePanel() {
  document.getElementById('side-panel')?.classList.remove('open');
}

window.investigateNodeUser = function(accId) {
  closeSidePanel();
  const input = document.getElementById('analyst-query-input');
  if (input) input.value = accId;
  currentQuery = accId;
  executeFullInvestigation(accId, true);
};

/**
 * Setup SVG Mouse Viewport Pan & Node Dragging Event Handlers
 */
function setupGraphInteractions() {
  const svg = document.getElementById('graph-svg');
  if (!svg) return;

  svg.addEventListener('mousedown', (e) => {
    if (e.target.id === 'graph-svg' || e.target.tagName === 'rect') {
      isPanningView = true;
      panStart = { x: e.clientX - transform.translateX, y: e.clientY - transform.translateY };
    }
  });

  svg.addEventListener('mousemove', (e) => {
    if (isDraggingNode && draggedNodeId) {
      const pt = getSVGPoint(e);
      nodePositions[draggedNodeId] = {
        x: pt.x - dragOffset.x,
        y: pt.y - dragOffset.y
      };
      if (graphData) renderGraph(graphData);
    } else if (isPanningView) {
      transform.translateX = e.clientX - panStart.x;
      transform.translateY = e.clientY - panStart.y;
      applyViewportTransform();
    }
  });

  svg.addEventListener('mouseup', () => {
    isDraggingNode = false;
    draggedNodeId = null;
    isPanningView = false;
  });

  svg.addEventListener('mouseleave', () => {
    isDraggingNode = false;
    draggedNodeId = null;
    isPanningView = false;
  });
}

function getSVGPoint(e) {
  const svg = document.getElementById('graph-svg');
  const pt = svg.createSVGPoint();
  pt.x = e.clientX;
  pt.y = e.clientY;
  const cursorPt = pt.matrixTransform(svg.getScreenCTM().inverse());
  return {
    x: (cursorPt.x - transform.translateX) / transform.scale,
    y: (cursorPt.y - transform.translateY) / transform.scale
  };
}

function zoomViewport(factor) {
  transform.scale *= factor;
  transform.scale = Math.min(3, Math.max(0.4, transform.scale));
  applyViewportTransform();
}

function resetViewport() {
  transform = { scale: 1, translateX: 0, translateY: 0 };
  applyViewportTransform();
}

function applyViewportTransform() {
  const group = document.getElementById('viewport-group');
  if (group) {
    group.setAttribute('transform', `translate(${transform.translateX}, ${transform.translateY}) scale(${transform.scale})`);
  }
}

function truncateString(str, num) {
  if (!str) return '';
  if (str.length <= num) return str;
  return str.slice(0, num) + '...';
}
