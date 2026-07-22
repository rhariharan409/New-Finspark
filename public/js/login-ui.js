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

  function showAlert(msg, isSuccess = false) {
    if (!alertEl) return;
    alertEl.textContent = msg;
    alertEl.className = isSuccess ? 'alert alert-success' : 'alert alert-danger';
    alertEl.style.display = 'block';
  }

  function hideAlert() {
    if (alertEl) alertEl.style.display = 'none';
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

        if (!response.ok || !data.success) {
          return showAlert(data.message || 'Login failed. Invalid credentials.');
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
