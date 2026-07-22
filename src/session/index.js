/**
 * Session Management Area
 * Handles user authentication sessions and protection middleware for Bank of Turtles.
 */

export const sessionModule = {
  name: 'session',

  /**
   * Middleware to enforce authenticated session on protected routes
   */
  requireAuth(req, res, next) {
    if (req.session && req.session.userId) {
      return next();
    }
    return res.status(401).json({
      success: false,
      message: 'Unauthorized. Active session required.'
    });
  },

  /**
   * Helper to format safe session payload
   */
  setSessionUser(req, user) {
    const userId = user.user_id || user.id;
    const accountId = user.account_id || user.accountNumber;
    const fullName = user.full_name || user.fullName;

    req.session.userId = userId;
    req.session.username = user.username || user.email;
    req.session.user = {
      user_id: userId,
      account_id: accountId,
      full_name: fullName,
      email: user.email,
      account_status: user.account_status || 'active'
    };
  },

  /**
   * Clear active user session
   */
  destroySession(req) {
    return new Promise((resolve, reject) => {
      if (!req.session) return resolve(true);
      req.session.destroy((err) => {
        if (err) return reject(err);
        resolve(true);
      });
    });
  }
};
