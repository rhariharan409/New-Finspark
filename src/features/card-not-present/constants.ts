/**
 * Card Not Present (CNP) Constants & Risk Weight Definitions
 */

export const CNP_RISK_WEIGHTS = {
  // Cybersecurity Risk Factors (+)
  UNKNOWN_DEVICE: 20,
  VPN_DETECTED: 15,
  PROXY_DETECTED: 15,
  IMPOSSIBLE_TRAVEL: 30,
  MULTIPLE_FAILED_OTP: 10,
  FAILED_LOGIN_ATTEMPTS: 12,
  ROOTED_JAILBROKEN: 25,
  PUBLIC_WIFI: 10,

  // Transaction Behavioral Risk Factors (+)
  HIGH_AMOUNT_OUTLIER: 18,
  NEW_MERCHANT: 12,
  NEW_CARD: 10,
  HIGH_VELOCITY: 20,
  INTERNATIONAL_PAYMENT: 15,
  HIGH_RISK_CATEGORY: 15,

  // Trust Mitigants (-)
  KNOWN_DEVICE: -10,
  TRUSTED_MERCHANT: -5,
  PREVIOUS_BEHAVIOUR_MATCH: -15,
  BIOMETRIC_VERIFIED: -10,
  HOME_WIFI: -5
};

export const RISK_LEVEL_THRESHOLDS = {
  APPROVE_MAX: 30,         // 0 - 30 -> Approve (Green)
  REQUIRE_OTP_MAX: 60,     // 31 - 60 -> Require OTP (Yellow)
  HOLD_TRANSACTION_MAX: 80, // 61 - 80 -> Hold Transaction (Orange)
  BLOCK_TRANSACTION_MIN: 81 // 81 - 100 -> Block Transaction (Red)
};

export const RISK_DECISION_CONFIG = {
  APPROVE: {
    label: 'Approve Transaction',
    description: 'Low fraud probability detected. Transaction passed all security telemetry checks.',
    color: '#059669',
    bgColor: '#ecfdf5',
    borderColor: '#10b981',
    badgeClass: 'bg-emerald-100 text-emerald-800',
    icon: '✅'
  },
  REQUIRE_OTP: {
    label: 'Require Step-Up OTP Verification',
    description: 'Moderate risk signals detected. Additional 2FA authentication required before release.',
    color: '#d97706',
    bgColor: '#fffbeb',
    borderColor: '#f59e0b',
    badgeClass: 'bg-amber-100 text-amber-800',
    icon: '🔐'
  },
  HOLD_TRANSACTION: {
    label: 'Hold Transaction for Analyst Review',
    description: 'High risk anomaly flagged. Payment placed on temporary hold for SOC verification.',
    color: '#ea580c',
    bgColor: '#fff7ed',
    borderColor: '#f97316',
    badgeClass: 'bg-orange-100 text-orange-800',
    icon: '⚠️'
  },
  BLOCK_TRANSACTION: {
    label: 'Block Transaction',
    description: 'Critical CNP fraud signature matched. Automated prevention engine blocked payment.',
    color: '#dc2626',
    bgColor: '#fef2f2',
    borderColor: '#ef4444',
    badgeClass: 'bg-red-100 text-red-800',
    icon: '🛑'
  }
};

export const MERCHANT_CATEGORIES = [
  'E-Commerce',
  'Travel & Airlines',
  'Electronics & Retail',
  'Gaming & Gambling',
  'Luxury Goods',
  'Utility Payments',
  'Subscriptions'
] as const;
