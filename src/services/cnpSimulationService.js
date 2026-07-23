/**
 * FINSPARK - Card-Not-Present (CNP) Fraud Attack Simulation Service Module
 * Processes synthetic CNP fraud attack scenarios, evaluates multi-factor environmental & behavioral risk,
 * records risk decisions in Supabase PostgreSQL database, logs security telemetry, dispatches SMS notifications,
 * and forwards simulation results to the Analyst section queue.
 */

import { atoVerificationService } from './atoVerificationService.js';
import { riskAnalysisService } from './riskAnalysisService.js';
import { riskRepository } from '../db/riskRepository.js';
import { transactionRepository } from '../db/transactionRepository.js';
import { telemetryRepository } from '../db/telemetryRepository.js';
import { smsService } from './smsService.js';
import { identityService } from '../security/identityService.js';
import { userRepository } from '../db/userRepository.js';

export const cnpSimulationService = {
  /**
   * Processes a synthetic CNP Fraud Attack Simulation
   */
  async processCnpAttackSimulation(payload = {}) {
    const {
      simulationMode = 'CNP_ATTACK',
      scenario = 'ACCOUNT_TAKEOVER_CNP',
      sessionId = 'SES-9C213624',
      cardToken = 'DEMO-TOKEN-4521',
      cardNetwork = 'VISA',
      lastFourDigits = '4521',
      cardholderName = 'HARI DEMO',
      cardProfileType = 'SYNTHETIC_STOLEN',
      transactionAmount = 85000,
      merchantName = 'Unknown Electronics Marketplace',
      merchantCategory = 'ELECTRONICS',
      channel = 'ONLINE',
      shippingBillingRelation = 'HIGH_RISK_MISMATCH',
      velocity = '3 attempts in 10 mins',
      failedAttempts = 2,
      clientEnv = {}
    } = payload;

    const cleanSessionId = (sessionId || 'SES-9C213624').trim();
    const amount = parseFloat(transactionAmount) || 85000;

    // 1. Evaluate Itemized Environmental Security Verification Checks
    const evalResult = await atoVerificationService.evaluateSessionSecurityChecks({
      sessionId: cleanSessionId,
      currentEnv: clientEnv
    });

    // 2. Resolve User & Baseline Profiles
    let userId = 'usr_1784708207810_eppkh';
    let userRecord = null;
    try {
      userRecord = await userRepository.findUserById(userId);
    } catch (e) {}

    // 3. Compute Itemized CNP Risk Factors & Weighted Scoring
    let deviceRisk = 0;
    let browserRisk = 0;
    let networkRisk = 0;
    let locationRisk = 0;
    let transactionAmountRisk = 0;
    let merchantRisk = 0;
    let behavioralDnaRisk = 0;

    const mismatches = evalResult.checks || [];

    mismatches.forEach(check => {
      if (!check.passed) {
        if (check.check === 'Device Fingerprint') deviceRisk = 40;
        if (check.check === 'Browser Environment') browserRisk = 20;
        if (check.check === 'IP Address') networkRisk = 15;
        if (check.check === 'Geographic Location') locationRisk = 20;
      }
    });

    // CNP Channel & Behavioral Anomalies
    if (amount > 50000) transactionAmountRisk = 25;
    else if (amount > 15000) transactionAmountRisk = 15;

    if (merchantCategory === 'ELECTRONICS' || merchantCategory === 'DIGITAL_GOODS' || merchantCategory === 'TRAVEL') {
      merchantRisk = 10;
    }

    if (shippingBillingRelation === 'HIGH_RISK_MISMATCH' || cardProfileType === 'SYNTHETIC_STOLEN') {
      behavioralDnaRisk = 25;
    }

    const totalWeightedRisk = Math.min(100, deviceRisk + browserRisk + networkRisk + locationRisk + transactionAmountRisk + merchantRisk + behavioralDnaRisk);

    let riskLevel = 'LOW';
    let decision = 'ALLOW';
    if (totalWeightedRisk >= 80) {
      riskLevel = 'CRITICAL';
      decision = 'BLOCK';
    } else if (totalWeightedRisk >= 60) {
      riskLevel = 'HIGH';
      decision = 'BLOCK';
    } else if (totalWeightedRisk >= 30) {
      riskLevel = 'MEDIUM';
      decision = 'ALLOW';
    }

    // 4. Construct Detection Rationale Reasons
    const detectionReasons = [];
    if (deviceRisk > 0) detectionReasons.push('❌ Device fingerprint mismatch (Trusted baseline vs Attacker device)');
    if (browserRisk > 0) detectionReasons.push('❌ Browser environment mismatch (Edge vs Attacker Chrome)');
    if (networkRisk > 0) detectionReasons.push('❌ New suspicious network IP address');
    if (locationRisk > 0) detectionReasons.push('❌ Geographic location anomaly (Chennai vs New Location)');
    if (transactionAmountRisk > 0) detectionReasons.push(`❌ Transaction amount (₹${amount.toLocaleString()}) deviates from typical user baseline (₹2,500)`);
    if (merchantRisk > 0) detectionReasons.push(`❌ High-risk merchant category (${merchantCategory})`);
    if (behavioralDnaRisk > 0) detectionReasons.push('❌ Transaction DNA mismatch (Card-Not-Present synthetic stolen card profile)');

    // 5. Create Pending / Blocked Transaction Record
    const transactionId = identityService.generateTransactionId();
    try {
      await transactionRepository.createTransaction({
        transaction_id: transactionId,
        session_id: cleanSessionId,
        sender_user_id: userId,
        receiver_user_id: 'usr_receiver_cnp_demo',
        amount: amount,
        currency: 'INR',
        transaction_type: 'cnp_transfer',
        transaction_status: decision === 'BLOCK' ? 'BLOCKED' : 'COMPLETED',
        transaction_timestamp: new Date().toISOString(),
        description: `Synthetic CNP Fraud Simulation: ${merchantName} (${merchantCategory})`
      });
    } catch (e) {}

    // 6. Persist Risk Decision in Database
    let riskDecisionRecord = null;
    try {
      riskDecisionRecord = await riskRepository.createRiskDecision({
        transaction_id: transactionId,
        user_id: userId,
        session_id: cleanSessionId,
        risk_score: totalWeightedRisk,
        risk_level: riskLevel,
        decision: decision,
        risk_factors: detectionReasons,
        baseline_snapshot: {
          simulation_type: 'CARD_NOT_PRESENT_FRAUD',
          scenario: scenario,
          card_last_four: lastFourDigits,
          card_network: cardNetwork,
          merchant_name: merchantName,
          merchant_category: merchantCategory,
          channel: channel,
          amount: amount,
          device_risk: deviceRisk,
          browser_risk: browserRisk,
          network_risk: networkRisk,
          location_risk: locationRisk,
          amount_risk: transactionAmountRisk,
          merchant_risk: merchantRisk,
          dna_risk: behavioralDnaRisk,
          velocity: velocity,
          failed_attempts: failedAttempts
        }
      });
    } catch (e) {}

    // 7. Log Security Telemetry Event
    try {
      await telemetryRepository.createTelemetryEvent({
        event_id: identityService.generateEventId(),
        session_id: cleanSessionId,
        user_id: userId,
        event_type: 'CNP_FRAUD_ATTACK_SIMULATED',
        event_category: 'security_alert',
        transaction_id: transactionId,
        metadata: {
          scenario,
          card_last_four: lastFourDigits,
          risk_score: totalWeightedRisk,
          decision,
          merchantName
        }
      });
    } catch (e) {}

    // 8. Dispatch Real Cellular SMS Notification to +91 9025521474
    const userPhone = userRecord?.phone || userRecord?.mobile || '+91 9025521474';
    try {
      await smsService.sendSms({
        toPhone: userPhone,
        message: `FINSPARK SECURITY ALERT: CNP Fraud Attempt of ₹${amount.toLocaleString()} at ${merchantName} was BLOCKED (Risk: ${totalWeightedRisk}/100 - ${riskLevel}).`,
        transactionId: transactionId
      });
    } catch (e) {}

    // 9. Return Structured Simulation Payload for Frontend & Analyst Queue
    return {
      success: true,
      simulationId: `SIM-CNP-${Date.now().toString(36).toUpperCase()}`,
      transactionId,
      sessionId: cleanSessionId,
      userPhone,
      cardProfile: {
        cardNetwork,
        lastFourDigits,
        expiry: '12/29',
        cvv: '•••',
        cardholderName,
        cardStatus: 'ACTIVE / SIMULATED'
      },
      cnpDetails: {
        amount,
        merchantName,
        merchantCategory,
        channel,
        shippingBillingRelation,
        velocity,
        failedAttempts
      },
      baselineDna: {
        typicalAmount: '₹2,500',
        typicalTime: '6:00 PM – 11:00 PM',
        typicalLocation: 'Chennai',
        typicalDevice: 'Trusted Laptop (Edge)',
        typicalCategories: 'Food, Shopping, Subscriptions',
        typicalFrequency: '3 transactions per week'
      },
      attackDna: {
        amount: `₹${amount.toLocaleString()}`,
        time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        location: clientEnv.location || 'New Suspicious Location',
        device: `${clientEnv.browserName || 'Chrome'} on ${clientEnv.operatingSystem || 'Windows'}`,
        merchant: `${merchantName} (${merchantCategory})`
      },
      riskBreakdown: {
        deviceRisk,
        browserRisk,
        networkRisk,
        locationRisk,
        transactionAmountRisk,
        merchantRisk,
        behavioralDnaRisk,
        totalRiskScore: totalWeightedRisk,
        riskLevel,
        decision
      },
      detectionReasons,
      recommendedActions: [
        '🔒 BLOCK TRANSACTION',
        '📊 CREATE RISK DECISION',
        '🚨 CREATE SECURITY EVENT',
        '💬 TRIGGER USER SMS ALERT',
        '🧾 STORE AUDIT EVENT'
      ],
      timestamp: new Date().toISOString()
    };
  }
};
