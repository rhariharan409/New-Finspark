/**
 * FINSPARK - Signup UI Controller
 * Manages user registration form submit and redirects to login.html on success.
 */

document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('signup-form');
  const alertEl = document.getElementById('signup-alert');
  const nameInput = document.getElementById('signup-name');
  const emailInput = document.getElementById('signup-email');
  const passwordInput = document.getElementById('signup-password');
  const confirmInput = document.getElementById('signup-confirm-password');
  const submitBtn = document.getElementById('signup-submit-btn');

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

      const fullName = nameInput ? nameInput.value.trim() : '';
      const email = emailInput ? emailInput.value.trim() : '';
      const password = passwordInput ? passwordInput.value : '';
      const confirmPassword = confirmInput ? confirmInput.value : '';

      if (!fullName || !email || !password || !confirmPassword) {
        return showAlert('All fields are required.');
      }

      if (password !== confirmPassword) {
        return showAlert('Passwords do not match.');
      }

      if (password.length < 6) {
        return showAlert('Password must be at least 6 characters long.');
      }

      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.textContent = 'Creating Account...';
      }

      try {
        const response = await fetch('/api/auth/signup', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ fullName, email, password, confirmPassword })
        });

        const data = await response.json();

        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.textContent = 'Create Account';
        }

        if (!response.ok || !data.success) {
          return showAlert(data.message || 'Registration failed. Please try again.');
        }

        showAlert('Account created successfully! Redirecting to Login...', true);
        setTimeout(() => {
          window.location.href = 'login.html';
        }, 1200);

      } catch (err) {
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.textContent = 'Create Account';
        }
        showAlert('A network error occurred. Please check your connection and try again.');
      }
    });
  }
});
