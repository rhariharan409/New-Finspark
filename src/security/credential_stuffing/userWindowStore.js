/**
 * User Sliding Window Store (Person 2: SK)
 * Tracks login events per user account (entity_id) over a sliding time window (default: 120 seconds / 2 minutes).
 */

export class UserWindowStore {
  constructor(windowSeconds = 120) {
    this.windowMs = windowSeconds * 1000;
    this.store = new Map();
  }

  _cleanupOldEvents(userData, nowMs) {
    const cutoff = nowMs - this.windowMs;
    const initialCount = userData.events.length;

    userData.events = userData.events.filter(e => e.timestampMs >= cutoff);

    if (userData.events.length < initialCount) {
      userData.failedCount = 0;
      userData.sourceIpsSet = new Set();

      for (const event of userData.events) {
        if (!event.loginSuccess) {
          userData.failedCount += 1;
        }
        if (event.ipAddress) {
          userData.sourceIpsSet.add(event.ipAddress);
        }
      }
    }
  }

  recordEvent(entityId, ipAddress = '', timestamp = new Date(), loginSuccess = false) {
    if (!entityId) return;

    const nowMs = timestamp instanceof Date ? timestamp.getTime() : new Date(timestamp).getTime();

    if (!this.store.has(entityId)) {
      this.store.set(entityId, {
        events: [],
        failedCount: 0,
        sourceIpsSet: new Set()
      });
    }

    const userData = this.store.get(entityId);
    this._cleanupOldEvents(userData, nowMs);

    userData.events.push({
      timestampMs: nowMs,
      ipAddress,
      loginSuccess: Boolean(loginSuccess)
    });

    if (!loginSuccess) {
      userData.failedCount += 1;
    }
    if (ipAddress) {
      userData.sourceIpsSet.add(ipAddress);
    }
  }

  getUserState(entityId, currentTimestamp = new Date()) {
    if (!entityId || !this.store.has(entityId)) {
      return {
        timestamps: [],
        failed_count: 0,
        source_ips_set: new Set()
      };
    }

    const nowMs = currentTimestamp instanceof Date ? currentTimestamp.getTime() : new Date(currentTimestamp).getTime();
    const userData = this.store.get(entityId);
    this._cleanupOldEvents(userData, nowMs);

    return {
      timestamps: userData.events.map(e => new Date(e.timestampMs)),
      failed_count: userData.failedCount,
      source_ips_set: new Set(userData.sourceIpsSet)
    };
  }

  clear() {
    this.store.clear();
  }
}
