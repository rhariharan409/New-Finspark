/**
 * Rule R4: Velocity Spike Detection
 * Checks whether an IP address is sending login requests at machine speed (>20 in 60s),
 * suggesting bot automation.
 */

export function checkVelocitySpike(ipState = {}, ipAddress = '', currentTimestamp = new Date()) {
  const timestamps = ipState.timestamps || [];
  if (!timestamps.length) {
    return {
      score_contribution: 0.0,
      reason: null,
      evidence: {}
    };
  }

  const nowMs = currentTimestamp instanceof Date ? currentTimestamp.getTime() : new Date(currentTimestamp).getTime();
  const cutoffMs = nowMs - 60000; // Last 60 seconds

  const recentEvents = timestamps.filter(ts => {
    const tsMs = ts instanceof Date ? ts.getTime() : new Date(ts).getTime();
    return tsMs >= cutoffMs;
  });

  const eventsLastMinute = recentEvents.length;

  if (eventsLastMinute >= 3) {
    const reason = `Velocity anomaly: ${eventsLastMinute} login events from IP ${ipAddress} in the last 60 seconds`;
    const evidence = {
      rule: 'velocity_spike',
      ip_address: ipAddress,
      events_last_minute: eventsLastMinute,
      confidence: 'high'
    };

    return {
      score_contribution: 70.0,
      reason,
      evidence
    };
  }

  return {
    score_contribution: 0.0,
    reason: null,
    evidence: {}
  };
}
