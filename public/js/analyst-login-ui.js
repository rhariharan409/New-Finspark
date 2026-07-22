/**
 * Cyber Analyst Portal Login Controller
 */

document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('analyst-login-form');
  const alertEl = document.getElementById('analyst-alert');
  const emailInput = document.getElementById('analyst-email');
  const passwordInput = document.getElementById('analyst-password');
  const submitBtn = document.getElementById('analyst-submit-btn');

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

      const email = emailInput.value.trim();
      const password = passwordInput.value.trim();

      if (!email || !password) {
        return showAlert('Please enter both analyst email and password.');
      }

      submitBtn.disabled = true;
      submitBtn.textContent = 'Authenticating Analyst...';

      try {
        const res = await fetch('/api/analyst/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify({ email, password })
        });

        const data = await res.json();
        submitBtn.disabled = false;
        submitBtn.textContent = 'Sign In to Analyst Portal';

        if (!res.ok || !data.success) {
          return showAlert(data.message || 'Authentication failed.');
        }

        showAlert('Authentication Successful! Accessing Cyber Console...', true);
        setTimeout(() => {
          window.location.href = data.redirectUrl || 'analyst.html';
        }, 500);

      } catch (err) {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Sign In to Analyst Portal';
        showAlert('Network error occurred during analyst login.');
      }
    });
  }
});
