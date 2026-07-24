/**
 * Password Hash Sliding Window Store (Person 2: SK)
 * Tracks password hash attempts across distinct entity IDs over a sliding time window (default: 600 seconds / 10 minutes).
 */

export class PasswordHashWindowStore {
  constructor(windowSeconds = 600) {
    this.windowMs = windowSeconds * 1000;
    this.store = new Map();
  }

  _cleanupOldEvents(hashData, nowMs) {
    const cutoff = nowMs - this.windowMs;
    const initialCount = hashData.events.length;

    hashData.events = hashData.events.filter(e => e.timestampMs >= cutoff);

    if (hashData.events.length < initialCount) {
      hashData.distinctUsersSet = new Set();
      for (const event of hashData.events) {
        hashData.distinctUsersSet.add(event.entityId);
      }
    }
  }

  recordEvent(passwordHash, entityId, timestamp = new Date()) {
    if (!passwordHash || !entityId) return;

    const nowMs = timestamp instanceof Date ? timestamp.getTime() : new Date(timestamp).getTime();

    if (!this.store.has(passwordHash)) {
      this.store.set(passwordHash, {
        events: [],
        distinctUsersSet: new Set()
      });
    }

    const hashData = this.store.get(passwordHash);
    this._cleanupOldEvents(hashData, nowMs);

    hashData.events.push({
      timestampMs: nowMs,
      entityId
    });

    hashData.distinctUsersSet.add(entityId);
  }

  getHashState(passwordHash, currentTimestamp = new Date()) {
    if (!passwordHash || !this.store.has(passwordHash)) {
      return {
        timestamps: [],
        distinct_users_set: new Set()
      };
    }

    const nowMs = currentTimestamp instanceof Date ? currentTimestamp.getTime() : new Date(currentTimestamp).getTime();
    const hashData = this.store.get(passwordHash);
    this._cleanupOldEvents(hashData, nowMs);

    return {
      timestamps: hashData.events.map(e => new Date(e.timestampMs)),
      distinct_users_set: new Set(hashData.distinctUsersSet)
    };
  }

  clear() {
    this.store.clear();
  }
}
