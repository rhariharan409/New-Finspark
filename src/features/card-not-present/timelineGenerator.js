/**
 * Fraud Timeline Event Generator for Card Not Present (CNP) Transactions (JS Runtime)
 */

export class TimelineGenerator {
  generateFraudTimeline(telemetry, transaction, riskResult) {
    const events = [];
    const baseTime = new Date();

    const formatOffsetTime = (secondsOffset) => {
      const t = new Date(baseTime.getTime() + secondsOffset * 1000);
      return t.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
    };

    // Step 1: Customer Login
    events.push({
      id: 'EVT-01',
      timestamp: formatOffsetTime(-180),
      title: 'Customer Session Authenticated',
      severity: telemetry.failedLoginAttempts > 0 ? 'MEDIUM' : 'LOW',
      icon: '👤',
      description: `User logged into digital banking portal from ${telemetry.currentCity}. (${telemetry.failedLoginAttempts} failed prior attempts)`,
      stage: 'LOGIN'
    });

    // Step 2: Cybersecurity Telemetry Analysis
    if (telemetry.deviceStatus === 'Unknown Device') {
      events.push({
        id: 'EVT-02A',
        timestamp: formatOffsetTime(-150),
        title: 'Unknown Hardware Device Detected',
        severity: 'HIGH',
        icon: '💻',
        description: `Unrecognized device fingerprint (${telemetry.deviceFingerprint}). Operating system: ${telemetry.os}, Browser: ${telemetry.browser}.`,
        stage: 'TELEMETRY'
      });
    } else {
      events.push({
        id: 'EVT-02B',
        timestamp: formatOffsetTime(-150),
        title: 'Registered Hardware Device Verified',
        severity: 'LOW',
        icon: '📱',
        description: `Device fingerprint matches customer registered hardware profile.`,
        stage: 'TELEMETRY'
      });
    }

    // Step 3: Network & Location Checks
    if (telemetry.vpnDetected || telemetry.proxyDetected) {
      events.push({
        id: 'EVT-03A',
        timestamp: formatOffsetTime(-120),
        title: 'Anonymizing Network Tunnel Detected',
        severity: 'HIGH',
        icon: '🌐',
        description: `Active ${telemetry.vpnDetected ? 'VPN' : ''} ${telemetry.proxyDetected ? 'Proxy' : ''} connection detected. IP: ${telemetry.ipAddress}.`,
        stage: 'TELEMETRY'
      });
    }

    if (telemetry.impossibleTravel) {
      events.push({
        id: 'EVT-03B',
        timestamp: formatOffsetTime(-100),
        title: 'Impossible Travel Jump Flagged',
        severity: 'CRITICAL',
        icon: '✈️',
        description: `Location jump from ${telemetry.previousCity} to ${telemetry.currentCity} flagged as physically impossible velocity.`,
        stage: 'TELEMETRY'
      });
    }

    // Step 4: Card Details & Transaction Details Entered
    events.push({
      id: 'EVT-04',
      timestamp: formatOffsetTime(-60),
      title: 'Card Payment Initiated',
      severity: 'LOW',
      icon: '💳',
      description: `Card ending in ${transaction.cardNumber.slice(-4)} entered for merchant '${transaction.merchantName}' (${transaction.merchantCategory}).`,
      stage: 'PAYMENT_INPUT'
    });

    // Step 5: Amount & Velocity Evaluation
    const ratio = transaction.previousAverageAmount > 0 ? (transaction.amount / transaction.previousAverageAmount).toFixed(1) : '1.0';
    events.push({
      id: 'EVT-05',
      timestamp: formatOffsetTime(-30),
      title: 'Payment Amount & Velocity Evaluated',
      severity: parseFloat(ratio) > 2.5 ? 'HIGH' : 'LOW',
      icon: '📊',
      description: `Amount: ₹${transaction.amount.toLocaleString()} (${ratio}x user avg). Velocity: ${transaction.velocityLastMinute} txns/min.`,
      stage: 'RISK_ANALYSIS'
    });

    // Step 6: AI Risk Scoring Computed
    const topReason = riskResult.reasons.find(r => r.type === 'POSITIVE_RISK')?.title || 'Standard Baseline Evaluated';
    events.push({
      id: 'EVT-06',
      timestamp: formatOffsetTime(-10),
      title: `AI Risk Score Calculated: ${riskResult.score} / 100`,
      severity: riskResult.score > 60 ? 'HIGH' : riskResult.score > 30 ? 'MEDIUM' : 'LOW',
      icon: '🧠',
      description: `Evaluated ${riskResult.reasons.length} risk factors. Primary factor: ${topReason}.`,
      stage: 'RISK_ANALYSIS'
    });

    // Step 7: Final Decision Enforcement
    let decisionTitle = '';
    let decisionSeverity = 'LOW';
    let decisionIcon = '✅';

    switch (riskResult.recommendation) {
      case 'APPROVE':
        decisionTitle = 'AI Engine Approved Payment';
        decisionSeverity = 'LOW';
        decisionIcon = '✅';
        break;
      case 'REQUIRE_OTP':
        decisionTitle = 'AI Engine Mandated Step-Up OTP Verification';
        decisionSeverity = 'MEDIUM';
        decisionIcon = '🔐';
        break;
      case 'HOLD_TRANSACTION':
        decisionTitle = 'AI Engine Placed Transaction on Security Hold';
        decisionSeverity = 'HIGH';
        decisionIcon = '⚠️';
        break;
      case 'BLOCK_TRANSACTION':
        decisionTitle = 'AI Engine Blocked Fraudulent CNP Payment';
        decisionSeverity = 'CRITICAL';
        decisionIcon = '🛑';
        break;
    }

    events.push({
      id: 'EVT-07',
      timestamp: formatOffsetTime(0),
      title: decisionTitle,
      severity: decisionSeverity,
      icon: decisionIcon,
      description: `Final Risk Score: ${riskResult.score}/100. Status: ${riskResult.recommendation}.`,
      stage: 'DECISION'
    });

    return events;
  }
}

export const timelineGenerator = new TimelineGenerator();
