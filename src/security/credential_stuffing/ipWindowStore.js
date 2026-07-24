/**
 * IP Sliding Window Store (Person 2: SK)
 * Tracks login events per IP address over a sliding time window (default: 300 seconds / 5 minutes).
 */

export class IPWindowStore {
  constructor(windowSeconds = 300) {
    this.windowMs = windowSeconds * 1000;
    this.store = new Map();
  }

  _cleanupOldEvents(ipData, nowMs) {
    const cutoff = nowMs - this.windowMs;
    const initialCount = ipData.events.length;

    ipData.events = ipData.events.filter(e => e.timestampMs >= cutoff);

    if (ipData.events.length < initialCount) {
      ipData.failedCount = 0;
      ipData.successCount = 0;
      ipData.targetUsersSet = new Set();

      for (const event of ipData.events) {
        if (event.loginSuccess) {
          ipData.successCount += 1;
        } else {
          ipData.failedCount += 1;
        }
        ipData.targetUsersSet.add(event.entityId);
      }
    }
  }

  recordEvent(ipAddress, entityId, timestamp = new Date(), loginSuccess = false) {
    if (!ipAddress) return;

    const nowMs = timestamp instanceof Date ? timestamp.getTime() : new Date(timestamp).getTime();

    if (!this.store.has(ipAddress)) {
      this.store.set(ipAddress, {
        events: [],
        failedCount: 0,
        successCount: 0,
        targetUsersSet: new Set()
      });
    }

    const ipData = this.store.get(ipAddress);
    this._cleanupOldEvents(ipData, nowMs);

    ipData.events.push({
      timestampMs: nowMs,
      entityId,
      loginSuccess: Boolean(loginSuccess)
    });

    if (loginSuccess) {
      ipData.successCount += 1;
    } else {
      ipData.failedCount += 1;
    }
    ipData.targetUsersSet.add(entityId);
  }

  getIPState(ipAddress, currentTimestamp = new Date()) {
    if (!ipAddress || !this.store.has(ipAddress)) {
      return {
        timestamps: [],
        failed_count: 0,
        success_count: 0,
        target_users_set: new Set()
      };
    }

    const nowMs = currentTimestamp instanceof Date ? currentTimestamp.getTime() : new Date(currentTimestamp).getTime();
    const ipData = this.store.get(ipAddress);
    this._cleanupOldEvents(ipData, nowMs);

    return {
      timestamps: ipData.events.map(e => new Date(e.timestampMs)),
      failed_count: ipData.failedCount,
      success_count: ipData.successCount,
      target_users_set: new Set(ipData.targetUsersSet)
    };
  }

  clear() {
    this.store.clear();
  }
}
