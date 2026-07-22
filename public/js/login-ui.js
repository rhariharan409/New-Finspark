/**
 * FINSPARK - Login UI Controller
 * Manages user authentication form submit and redirects to dashboard.html on success.
 */

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
        submitBtn.textContent = 'Signing in...';
      }

      try {
        const response = await fetch('/api/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify({ identifier, password })
        });

        const data = await response.json();

        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.textContent = 'Sign In to Banking';
        }

        if (!response.ok || !data.success) {
          return showAlert(data.message || 'Login failed. Invalid credentials.');
        }

        showAlert('Sign in successful! Accessing banking dashboard...', true);
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
});
