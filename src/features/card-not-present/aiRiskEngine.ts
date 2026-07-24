/**
 * AI Risk Engine for Card Not Present (CNP) Fraud Detection
 * Calculates weighted risk score (0 - 100) from telemetry and transaction signals.
 */

import { CNPTelemetry, CNPTransaction, RiskEvaluationResult, RiskReason, RiskDecisionType } from './types/cnpTypes.js';
import { CNP_RISK_WEIGHTS, RISK_LEVEL_THRESHOLDS, RISK_DECISION_CONFIG } from './constants.js';

export class AIRiskEngine {
  /**
   * Evaluates CNP transaction against cybersecurity telemetry & behavioral features
   */
  public evaluateCNPRisk(telemetry: CNPTelemetry, transaction: CNPTransaction): RiskEvaluationResult {
    let rawScore = 15; // Base baseline score
    const reasons: RiskReason[] = [];

    // --- CYBERSECURITY TELEMETRY SIGNALS ---

    // 1. Device Evaluation
    if (telemetry.deviceStatus === 'Unknown Device') {
      const weight = CNP_RISK_WEIGHTS.UNKNOWN_DEVICE;
      rawScore += weight;
      reasons.push({
        id: 'UNKNOWN_DEVICE',
        title: 'Unknown Device Detected',
        weight: weight,
        type: 'POSITIVE_RISK',
        description: `Payment initiated from an unrecognized hardware environment (${telemetry.browser} on ${telemetry.os}).`
      });
    } else {
      const weight = CNP_RISK_WEIGHTS.KNOWN_DEVICE;
      rawScore += weight;
      reasons.push({
        id: 'KNOWN_DEVICE',
        title: 'Known Hardware Device',
        weight: weight,
        type: 'NEGATIVE_MITIGANT',
        description: 'Payment matches customer registered device fingerprint.'
      });
    }

    // 2. Impossible Travel
    if (telemetry.impossibleTravel) {
      const weight = CNP_RISK_WEIGHTS.IMPOSSIBLE_TRAVEL;
      rawScore += weight;
      reasons.push({
        id: 'IMPOSSIBLE_TRAVEL',
        title: 'Impossible Travel Anomaly',
        weight: weight,
        type: 'POSITIVE_RISK',
        description: `Physical distance jump detected from previous city (${telemetry.previousCity}) to current city (${telemetry.currentCity}) in unrealistically short timeframe.`
      });
    }

    // 3. VPN / Proxy Detection
    if (telemetry.vpnDetected) {
      const weight = CNP_RISK_WEIGHTS.VPN_DETECTED;
      rawScore += weight;
      reasons.push({
        id: 'VPN_DETECTED',
        title: 'VPN Tunneling Active',
        weight: weight,
        type: 'POSITIVE_RISK',
        description: `Encrypted virtual private network detected hiding origin IP address (${telemetry.ipAddress}).`
      });
    }

    if (telemetry.proxyDetected) {
      const weight = CNP_RISK_WEIGHTS.PROXY_DETECTED;
      rawScore += weight;
      reasons.push({
        id: 'PROXY_DETECTED',
        title: 'Proxy Relay Network',
        weight: weight,
        type: 'POSITIVE_RISK',
        description: 'Traffic relayed through an anonymizing proxy node.'
      });
    }

    // 4. Rooted / Jailbroken Device
    if (telemetry.rootedJailbroken) {
      const weight = CNP_RISK_WEIGHTS.ROOTED_JAILBROKEN;
      rawScore += weight;
      reasons.push({
        id: 'ROOTED_DEVICE',
        title: 'Rooted / Jailbroken OS',
        weight: weight,
        type: 'POSITIVE_RISK',
        description: 'Device operating system security sandbox has been bypassed.'
      });
    }

    // 5. Failed OTP / Login Attempts
    if (telemetry.otpAttempts > 1) {
      const weight = CNP_RISK_WEIGHTS.MULTIPLE_FAILED_OTP;
      rawScore += weight;
      reasons.push({
        id: 'FAILED_OTP',
        title: 'Multiple Failed OTP Attempts',
        weight: weight,
        type: 'POSITIVE_RISK',
        description: `${telemetry.otpAttempts} OTP authentication attempts logged prior to payment authorization.`
      });
    }

    if (telemetry.failedLoginAttempts > 0) {
      const weight = CNP_RISK_WEIGHTS.FAILED_LOGIN_ATTEMPTS;
      rawScore += weight;
      reasons.push({
        id: 'FAILED_LOGINS',
        title: 'Recent Failed Login Attempts',
        weight: weight,
        type: 'POSITIVE_RISK',
        description: `${telemetry.failedLoginAttempts} failed authentication attempt(s) recorded in current session.`
      });
    }

    // 6. Network Security
    if (telemetry.wifiCategory === 'Public WiFi') {
      const weight = CNP_RISK_WEIGHTS.PUBLIC_WIFI;
      rawScore += weight;
      reasons.push({
        id: 'PUBLIC_WIFI',
        title: 'Unsecured Public Wi-Fi',
        weight: weight,
        type: 'POSITIVE_RISK',
        description: 'Transaction performed over non-encrypted open public hotspot.'
      });
    } else if (telemetry.wifiCategory === 'Home WiFi') {
      const weight = CNP_RISK_WEIGHTS.HOME_WIFI;
      rawScore += weight;
      reasons.push({
        id: 'HOME_WIFI',
        title: 'Secure Trusted Home Network',
        weight: weight,
        type: 'NEGATIVE_MITIGANT',
        description: 'Connection originates from user known residential ISP access point.'
      });
    }

    // 7. Biometric Mitigant
    if (telemetry.biometricUsed) {
      const weight = CNP_RISK_WEIGHTS.BIOMETRIC_VERIFIED;
      rawScore += weight;
      reasons.push({
        id: 'BIOMETRIC_VERIFIED',
        title: 'Hardware Biometric Authenticated',
        weight: weight,
        type: 'NEGATIVE_MITIGANT',
        description: 'TouchID / FaceID hardware verification passed on payment device.'
      });
    }


    // --- TRANSACTION BEHAVIORAL SIGNALS ---

    // 8. Amount Anomaly (High value payment relative to historical average)
    const ratio = transaction.previousAverageAmount > 0 
      ? transaction.amount / transaction.previousAverageAmount 
      : 1;

    if (ratio >= 3.0 || transaction.amount > 50000) {
      const weight = CNP_RISK_WEIGHTS.HIGH_AMOUNT_OUTLIER;
      rawScore += weight;
      reasons.push({
        id: 'HIGH_AMOUNT',
        title: 'High Amount Outlier',
        weight: weight,
        type: 'POSITIVE_RISK',
        description: `Payment amount (₹${transaction.amount.toLocaleString()}) is ${ratio.toFixed(1)}x higher than user average historical transaction (₹${transaction.previousAverageAmount.toLocaleString()}).`
      });
    }

    // 9. Merchant & Category Risk
    if (transaction.isNewMerchant) {
      const weight = CNP_RISK_WEIGHTS.NEW_MERCHANT;
      rawScore += weight;
      reasons.push({
        id: 'NEW_MERCHANT',
        title: 'New / First-Time Merchant',
        weight: weight,
        type: 'POSITIVE_RISK',
        description: `Customer has no prior payment history with merchant (${transaction.merchantName}).`
      });
    }

    if (transaction.beneficiaryHistory === 'Trusted Recipient' || transaction.beneficiaryHistory === 'Frequent Merchant') {
      const weight = CNP_RISK_WEIGHTS.TRUSTED_MERCHANT;
      rawScore += weight;
      reasons.push({
        id: 'TRUSTED_MERCHANT',
        title: 'Trusted Beneficiary History',
        weight: weight,
        type: 'NEGATIVE_MITIGANT',
        description: 'Merchant is recorded as a verified frequent payment recipient.'
      });
    }

    if (transaction.merchantCategory === 'Gaming & Gambling' || transaction.merchantCategory === 'Luxury Goods') {
      const weight = CNP_RISK_WEIGHTS.HIGH_RISK_CATEGORY;
      rawScore += weight;
      reasons.push({
        id: 'HIGH_RISK_CATEGORY',
        title: 'High Risk Merchant Category',
        weight: weight,
        type: 'POSITIVE_RISK',
        description: `Merchant operates in sensitive high-chargeback sector (${transaction.merchantCategory}).`
      });
    }

    // 10. Velocity Anomaly
    if (transaction.velocityLastMinute >= 3 || transaction.velocityLastHour >= 8) {
      const weight = CNP_RISK_WEIGHTS.HIGH_VELOCITY;
      rawScore += weight;
      reasons.push({
        id: 'HIGH_VELOCITY',
        title: 'Abnormal Transaction Velocity',
        weight: weight,
        type: 'POSITIVE_RISK',
        description: `${transaction.velocityLastMinute} payments attempted in last minute (${transaction.velocityLastHour} in last hour).`
      });
    }

    // 11. International Payment
    if (transaction.isInternational) {
      const weight = CNP_RISK_WEIGHTS.INTERNATIONAL_PAYMENT;
      rawScore += weight;
      reasons.push({
        id: 'INTERNATIONAL_PAYMENT',
        title: 'Cross-Border International Payment',
        weight: weight,
        type: 'POSITIVE_RISK',
        description: `Payment currency (${transaction.currency}) processed via foreign acquiring bank.`
      });
    }

    // 12. New Card Flag
    if (transaction.isNewCard) {
      const weight = CNP_RISK_WEIGHTS.NEW_CARD;
      rawScore += weight;
      reasons.push({
        id: 'NEW_CARD',
        title: 'Recently Added Payment Card',
        weight: weight,
        type: 'POSITIVE_RISK',
        description: 'Payment card was linked less than 24 hours ago.'
      });
    }

    // 13. Previous Behavior Pattern Match Mitigant
    if (!telemetry.impossibleTravel && !telemetry.vpnDetected && telemetry.deviceStatus === 'Known Device' && ratio <= 1.5) {
      const weight = CNP_RISK_WEIGHTS.PREVIOUS_BEHAVIOUR_MATCH;
      rawScore += weight;
      reasons.push({
        id: 'BEHAVIOR_MATCH',
        title: 'Matches Historical Behavioral Profile',
        weight: weight,
        type: 'NEGATIVE_MITIGANT',
        description: 'Timing, device, network, and transaction size strictly align with user historical pattern.'
      });
    }

    // Clamp score between 0 and 100
    const score = Math.min(100, Math.max(0, Math.round(rawScore)));

    // Determine Risk Level & Recommendation Decision
    let recommendation: RiskDecisionType = 'APPROVE';
    let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'LOW';

    if (score <= RISK_LEVEL_THRESHOLDS.APPROVE_MAX) {
      recommendation = 'APPROVE';
      riskLevel = 'LOW';
    } else if (score <= RISK_LEVEL_THRESHOLDS.REQUIRE_OTP_MAX) {
      recommendation = 'REQUIRE_OTP';
      riskLevel = 'MEDIUM';
    } else if (score <= RISK_LEVEL_THRESHOLDS.HOLD_TRANSACTION_MAX) {
      recommendation = 'HOLD_TRANSACTION';
      riskLevel = 'HIGH';
    } else {
      recommendation = 'BLOCK_TRANSACTION';
      riskLevel = 'CRITICAL';
    }

    const config = RISK_DECISION_CONFIG[recommendation];

    return {
      score,
      riskLevel,
      recommendation,
      colorCode: config.color,
      reasons,
      evaluatedAt: new Date().toISOString()
    };
  }
}

export const aiRiskEngine = new AIRiskEngine();
