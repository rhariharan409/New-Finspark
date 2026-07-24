/**
 * Card Not Present (CNP) Fraud Detection Types
 * FINSPARK Cybersecurity Platform
 */

export interface CNPTelemetry {
  // Device Signals
  deviceStatus: 'Known Device' | 'Unknown Device';
  deviceFingerprint: string;
  browser: string;
  os: string;
  rootedJailbroken: boolean;

  // Location & Network Signals
  currentCity: string;
  previousCity: string;
  impossibleTravel: boolean;
  ipAddress: string;
  vpnDetected: boolean;
  proxyDetected: boolean;
  networkType: '5G' | '4G' | 'Wi-Fi' | 'Ethernet';
  wifiCategory: 'Public WiFi' | 'Home WiFi' | 'Cellular Data' | 'Corporate Network';

  // Session & Authentication Signals
  loginTime: string;
  sessionDurationSeconds: number;
  failedLoginAttempts: number;
  otpAttempts: number;
  biometricUsed: boolean;
}

export interface CNPTransaction {
  cardNumber: string;
  cardholderName: string;
  expiryDate: string;
  cvv: string;
  amount: number;
  currency: string;
  merchantName: string;
  merchantCategory: 'E-Commerce' | 'Travel & Airlines' | 'Electronics & Retail' | 'Gaming & Gambling' | 'Luxury Goods' | 'Utility Payments' | 'Subscriptions';
  
  // Historical & Velocity Features
  previousAverageAmount: number;
  isNewMerchant: boolean;
  isNewCard: boolean;
  paymentTimestamp: string;
  velocityLastMinute: number;
  velocityLastHour: number;
  beneficiaryHistory: 'Trusted Recipient' | 'First Time Beneficiary' | 'Known High Risk Merchant' | 'Frequent Merchant';
  isInternational: boolean;
}

export interface RiskReason {
  id: string;
  title: string;
  weight: number; // positive (+) increases risk, negative (-) decreases risk
  type: 'POSITIVE_RISK' | 'NEGATIVE_MITIGANT';
  description: string;
}

export type RiskDecisionType = 'APPROVE' | 'REQUIRE_OTP' | 'HOLD_TRANSACTION' | 'BLOCK_TRANSACTION';

export interface RiskEvaluationResult {
  score: number; // Clamped 0 - 100
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  recommendation: RiskDecisionType;
  colorCode: string;
  reasons: RiskReason[];
  evaluatedAt: string;
}

export type TimelineEventSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface TimelineEvent {
  id: string;
  timestamp: string;
  title: string;
  severity: TimelineEventSeverity;
  icon: string;
  description: string;
  stage: 'LOGIN' | 'TELEMETRY' | 'PAYMENT_INPUT' | 'RISK_ANALYSIS' | 'DECISION';
}

export interface SimulationScenario {
  id: string;
  name: string;
  subtitle: string;
  description: string;
  badge: string;
  badgeColor: string;
  telemetry: CNPTelemetry;
  transaction: CNPTransaction;
  expectedScoreRange: string;
  expectedDecision: RiskDecisionType;
}
