/**
 * Bank of Turtles - Dashboard Guard & Session Handler
 * Protects dashboard route, populates authenticated user data, and handles logout.
 */

document.addEventListener('DOMContentLoaded', () => {
  initDashboardGuard();
});

/**
 * Initialize Dashboard Protected Route & Session Verification
 */
async function initDashboardGuard() {
  const dashContainer = document.getElementById('dashboard-view');
  if (!dashContainer) return;

  try {
    const response = await fetch('/api/auth/me');
    const data = await response.json();

    // Redirect unauthenticated requests to Login page
    if (!response.ok || !data.authenticated || !data.user) {
      window.location.href = 'login.html';
      return;
    }

    const user = data.user;
    
    // Populate Authenticated User Profile & Details
    const nameEl = document.getElementById('user-display-name');
    const usernameEl = document.getElementById('user-display-username');
    const accNumberEl = document.getElementById('acc-display-number');
    const balanceEl = document.getElementById('acc-display-balance');

    if (nameEl) nameEl.textContent = user.full_name || user.fullName || 'Authenticated User';
    if (usernameEl) usernameEl.textContent = `User ID: ${user.user_id || user.id || 'USR-AUTHENTICATED'}`;
    if (accNumberEl) accNumberEl.textContent = user.account_id || user.accountNumber || 'ACC-DEFAULT';
    if (balanceEl) {
      const balance = user.balance !== undefined ? user.balance : 12500.00;
      balanceEl.textContent = `$${Number(balance).toLocaleString('en-US', { minimumFractionDigits: 2 })}`;
    }

    // Bind Logout Button
    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
      logoutBtn.addEventListener('click', async () => {
        try {
          await fetch('/api/auth/logout', { method: 'POST' });
          window.location.href = 'login.html';
        } catch (err) {
          console.error('Logout error:', err);
          window.location.href = 'login.html';
        }
      });
    }
  } catch (err) {
    console.error('Session guard verification failed:', err);
    window.location.href = 'login.html';
  }
}
