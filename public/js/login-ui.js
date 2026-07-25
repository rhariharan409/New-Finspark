/**
 * FINSPARK - Login UI & Client Environment Fingerprinting Controller
 * Captures real browser canvas/WebGL device fingerprints, screen resolution, timezone, language, and OS details upon user authentication.
 */

/**
 * Generates real HTML5 Canvas Device Fingerprint Hash
 */
function generateCanvasFingerprint() {
  try {
    const canvas = document.createElement('canvas');
    canvas.width = 200;
    canvas.height = 50;
    const ctx = canvas.getContext('2d');
    if (!ctx) return 'FP-CANVAS-UNSUPPORTED';

    ctx.textBaseline = 'top';
    ctx.font = "14px 'Arial'";
    ctx.textBaseline = 'alphabetic';
    ctx.fillStyle = '#f60';
    ctx.fillRect(125, 1, 62, 20);
    ctx.fillStyle = '#069';
    ctx.fillText('FINSPARK-SECURE-SESSION-FP', 2, 15);
    ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
    ctx.fillText('FINSPARK-SECURE-SESSION-FP', 4, 17);

    const dataUrl = canvas.toDataURL();
    let hash = 0;
    for (let i = 0; i < dataUrl.length; i++) {
      const char = dataUrl.charCodeAt(i);
      hash = (hash << 5) - hash + char;
      hash |= 0;
    }
    return `FP-CANVAS-${Math.abs(hash).toString(16).toUpperCase()}`;
  } catch (e) {
    return `FP-DEV-${Date.now().toString(36).toUpperCase()}`;
  }
}

/**
 * Collects real client browser, system, and device telemetry
 */
function collectRealClientEnvironment() {
  const ua = navigator.userAgent || '';
  let browserName = 'Chrome';
  let browserVersion = '126.0';
  let os = 'Windows';

  if (ua.includes('Firefox')) {
    browserName = 'Firefox';
    browserVersion = ua.split('Firefox/')[1]?.split(' ')[0] || '125.0';
  } else if (ua.includes('Edg')) {
    browserName = 'Edge';
    browserVersion = ua.split('Edg/')[1]?.split(' ')[0] || '124.0';
  } else if (ua.includes('Safari') && !ua.includes('Chrome')) {
    browserName = 'Safari';
    browserVersion = ua.split('Version/')[1]?.split(' ')[0] || '17.0';
  } else if (ua.includes('Chrome')) {
    browserName = 'Chrome';
    browserVersion = ua.split('Chrome/')[1]?.split(' ')[0] || '126.0';
  }

  const platform = navigator.platform || '';
  if (platform.includes('Win') || ua.includes('Windows')) os = 'Windows 11';
  else if (platform.includes('Mac') || ua.includes('Mac OS')) os = 'macOS';
  else if (platform.includes('Linux') || ua.includes('Linux')) os = 'Linux';
  else if (ua.includes('Android')) os = 'Android';
  else if (ua.includes('iPhone') || ua.includes('iPad')) os = 'iOS';

  const screenRes = `${window.screen.width || 1920}x${window.screen.height || 1080}`;
  const language = navigator.language || navigator.userLanguage || 'en-US';
  let timezone = 'Asia/Kolkata';
  try {
    timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || 'Asia/Kolkata';
  } catch (e) {}

  const deviceFingerprint = generateCanvasFingerprint();

  return {
    browserName,
    browserVersion,
    operatingSystem: os,
    userAgent: ua,
    screenResolution: screenRes,
    language,
    timezone,
    platform,
    deviceFingerprint
  };
}

document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('login-form');
  const alertEl = document.getElementById('login-alert');
  const emailInput = document.getElementById('login-email');
  const passwordInput = document.getElementById('login-password');
  const submitBtn = document.getElementById('login-submit-btn');

  function showAlert(msg, isSuccess = false, showUnblockBtn = false) {
    if (!alertEl) return;
    alertEl.innerHTML = `
      <div>${msg}</div>
      ${showUnblockBtn ? `
        <button id="alert-unblock-btn" style="margin-top: 0.75rem; background: #dc2626; color: #ffffff; border: none; padding: 0.4rem 0.85rem; border-radius: 6px; font-weight: 700; font-size: 0.8rem; cursor: pointer; display: inline-flex; align-items: center; gap: 0.35rem;">
          🔓 Click Here to Unblock Account / IP Now
        </button>
      ` : ''}
    `;
    alertEl.className = isSuccess ? 'alert alert-success' : 'alert alert-danger';
    alertEl.style.display = 'block';

    const alertUnblock = document.getElementById('alert-unblock-btn');
    if (alertUnblock) {
      alertUnblock.addEventListener('click', unblockEntity);
    }
  }

  function hideAlert() {
    if (alertEl) alertEl.style.display = 'none';
  }

  const scoreVal = document.getElementById('widget-score-val');
  const scoreBar = document.getElementById('widget-score-bar');
  const riskBadge = document.getElementById('widget-risk-badge');
  const reasonsDiv = document.getElementById('widget-reasons');
  const resetBtn = document.getElementById('reset-threat-btn');

  // Top-Right Floating Risk Score Increase Notification Toast & Sound Alert
  let lastKnownLoginRiskScore = 0;
  let riskToastTimer = null;

  function playRiskScoreAlertSound() {
    try {
      const AudioCtx = window.AudioContext || window.webkitAudioContext;
      if (!AudioCtx) return;
      const ctx = new AudioCtx();
      
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = 'sine';
      osc.frequency.setValueAtTime(600, ctx.currentTime);
      osc.frequency.exponentialRampToValueAtTime(880, ctx.currentTime + 0.15);
      
      gain.gain.setValueAtTime(0.15, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.35);
      
      osc.connect(gain);
      gain.connect(ctx.destination);
      
      osc.start(ctx.currentTime);
      osc.stop(ctx.currentTime + 0.35);
    } catch (e) {}
  }

  function updateRiskWidget(score = 0, level = 'LOW (ALLOW)', reasons = []) {
    const numScore = Math.min(100, Math.max(0, parseFloat(score) || 0));

    if (numScore > lastKnownLoginRiskScore && numScore > 0) {
      playRiskScoreAlertSound();
      showTopRightRiskToast(numScore, level, reasons);
    }
    lastKnownLoginRiskScore = numScore;
  }

  function showTopRightRiskToast(score, level, reasons = []) {
    let toast = document.getElementById('risk-score-top-toast');
    if (!toast) {
      toast = document.createElement('div');
      toast.id = 'risk-score-top-toast';
      toast.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        z-index: 100000;
        background: #001d35;
        color: #ffffff;
        border: 1px solid #00497b;
        border-left: 5px solid #ef4444;
        border-radius: 8px;
        padding: 1rem 1.25rem;
        box-shadow: 0 10px 30px rgba(0,0,0,0.35);
        max-width: 380px;
        font-family: 'IBM Plex Sans', sans-serif;
        animation: slideInRight 0.3s ease-out forwards;
      `;
      document.body.appendChild(toast);

      if (!document.getElementById('risk-toast-style')) {
        const style = document.createElement('style');
        style.id = 'risk-toast-style';
        style.textContent = `
          @keyframes slideInRight {
            from { transform: translateX(120%); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
          }
        `;
        document.head.appendChild(style);
      }
    }

    const borderLeftColor = score >= 70 ? '#ef4444' : score >= 45 ? '#f97316' : '#eab308';
    toast.style.borderLeftColor = borderLeftColor;

    const reasonText = reasons && reasons.length > 0 ? reasons.join('; ') : 'Bot signature / behavioral anomaly detected';

    toast.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: flex-start; gap: 0.75rem;">
        <div style="display: flex; align-items: center; gap: 0.5rem;">
          <span style="font-size: 1.2rem;">⚠️</span>
          <strong style="font-size: 0.92rem; color: #ffffff;">Security Notice: Risk Score Increased</strong>
        </div>
        <button onclick="document.getElementById('risk-score-top-toast')?.remove()" style="background: none; border: none; color: #94a3b8; font-size: 1.1rem; cursor: pointer; line-height: 1;">✕</button>
      </div>
      <div style="margin-top: 0.5rem; font-size: 0.85rem; color: #d0e4ff; display: flex; align-items: center; gap: 0.5rem;">
        <span>Risk Score:</span>
        <span style="background: ${borderLeftColor}33; color: ${borderLeftColor}; border: 1px solid ${borderLeftColor}66; padding: 0.15rem 0.5rem; border-radius: 4px; font-weight: 700; font-size: 0.78rem;">
          ${score}/100 (${level})
        </span>
      </div>
      <div style="margin-top: 0.4rem; font-size: 0.78rem; color: #cbd5e1;">
        <span style="color: #f87171; font-weight: 700;">Signals:</span> ${reasonText}
      </div>
    `;

    if (riskToastTimer) clearTimeout(riskToastTimer);
    riskToastTimer = setTimeout(() => {
      toast?.remove();
    }, 8000);
  }

  async function unblockEntity() {
    try {
      const res = await fetch('/api/auth/unblock-entity', { method: 'POST' });
      const data = await res.json();
      if (data.success) {
        updateRiskWidget(0, 'LOW (ALLOW)', []);
        showAlert('🟢 Account and IP have been successfully unblocked! You may now sign in.', true);
      }
    } catch (e) {
      console.error('Unblock error:', e);
    }
  }

  async function fetchLiveThreatStatus() {
    try {
      const id = emailInput ? emailInput.value.trim() : '';
      const res = await fetch(`/api/auth/current-threat-status?identifier=${encodeURIComponent(id || 'unknown')}`);
      const data = await res.json();
      if (res.ok && data.success) {
        updateRiskWidget(data.riskScore, data.riskLevel, data.reasons || []);
        if (data.isBlocked) {
          showAlert('Access blocked due to suspicious activity.', false, true);
        }
      }
    } catch (e) {}
  }

  // Poll live threat status every 1.5 seconds for real-time risk meter updates
  fetchLiveThreatStatus();
  setInterval(fetchLiveThreatStatus, 1500);

  if (emailInput) {
    emailInput.addEventListener('input', fetchLiveThreatStatus);
  }

  if (resetBtn) {
    resetBtn.addEventListener('click', unblockEntity);
  }

  if (form) {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      hideAlert();

      const identifier = emailInput ? emailInput.value.trim() : '';
      const password = passwordInput ? passwordInput.value : '';

      if (!identifier || !password) {
        return showAlert('Please enter your email/account ID and password.');
      }

      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.textContent = 'Signing in & verifying device fingerprint...';
      }

      const clientEnv = collectRealClientEnvironment();

      try {
        const response = await fetch('/api/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify({ identifier, password, clientEnv })
        });

        const data = await response.json();

        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.textContent = 'Sign In to Banking';
        }

        // Live Risk Score Update
        if (typeof data.riskScore !== 'undefined') {
          updateRiskWidget(data.riskScore, data.riskLevel, data.reasons || []);
        }

        if (!response.ok || !data.success) {
          const isBlocked = data.riskScore >= 70 || (data.message && data.message.toLowerCase().includes('blocked'));
          return showAlert(data.message || 'Login failed. Invalid credentials.', false, isBlocked);
        }

        showAlert('Sign in successful! Establishing trusted session environment...', true);
        setTimeout(() => {
          window.location.href = data.redirectUrl || 'dashboard.html';
        }, 500);

      } catch (err) {
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.textContent = 'Sign In to Banking';
        }
        showAlert('A network error occurred. Please check your connection and try again.');
      }
    });
  }

  // Floating Demo Widget: Single Session ID Login & ATO Live Verification
  const demoBtn = document.getElementById('demo-session-btn');
  const demoInput = document.getElementById('demo-session-input');

  if (demoBtn) {
    demoBtn.addEventListener('click', async (e) => {
      e.preventDefault();

      const sessionId = demoInput ? demoInput.value.trim() : '';
      if (!sessionId) {
        alert('Please enter a Session ID (e.g. SES-908C0B98).');
        return;
      }

      demoBtn.disabled = true;
      demoBtn.textContent = 'Verifying...';

      // Collect real client environment from current device
      const clientEnv = collectRealClientEnvironment();

      try {
        const res = await fetch('/api/auth/verify-session-id-login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ sessionId, clientEnv })
        });

        const data = await res.json();
        demoBtn.disabled = false;
        demoBtn.textContent = 'Login';

        if (res.ok && data.success) {
          alert(data.message || '🟢 Session Verified! Device specifications match trusted baseline. Logging into banking dashboard...');
          window.location.href = data.redirectUrl || 'dashboard.html';
        } else {
          // Show ONLY Popup Alert when access is denied
          alert(data.message || '🚫 ACCESS DENIED: Account Takeover (ATO) Detected!\n\nIncoming device specifications do not match trusted session baseline.');
        }
      } catch (err) {
        demoBtn.disabled = false;
        demoBtn.textContent = 'Login';
        alert('Network error verifying Session ID against database.');
      }
    });
  }
});
