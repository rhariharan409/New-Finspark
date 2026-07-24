/**
 * Baseline Tracker (Welford's Algorithm)
 * Maintains long-term running mean and standard deviation per entity using Welford's online algorithm
 * for memory-efficient adaptive anomaly thresholding.
 */

export class BaselineTracker {
  constructor(minHistoryCount = 10) {
    this.minHistoryCount = minHistoryCount;
    this.statsMap = new Map();
  }

  update(entityId, newValue) {
    if (!entityId) return;

    if (!this.statsMap.has(entityId)) {
      this.statsMap.set(entityId, {
        count: 0,
        mean: 0.0,
        varianceSum: 0.0
      });
    }

    const stats = this.statsMap.get(entityId);
    stats.count += 1;
    const count = stats.count;

    const delta = newValue - stats.mean;
    stats.mean += delta / count;
    const delta2 = newValue - stats.mean;
    stats.varianceSum += delta * delta2;
  }

  getStats(entityId) {
    if (!entityId || !this.statsMap.has(entityId)) {
      return {
        count: 0,
        mean: 0.0,
        varianceSum: 0.0,
        stdDev: 0.0
      };
    }

    const stats = this.statsMap.get(entityId);
    const count = stats.count;
    const stdDev = count > 1 ? Math.sqrt(stats.varianceSum / count) : 0.0;

    return {
      count,
      mean: stats.mean,
      varianceSum: stats.varianceSum,
      stdDev
    };
  }

  getThreshold(entityId, numStdDevs = 2.5, fallbackThreshold = 5.0) {
    const stats = this.getStats(entityId);
    const count = stats.count;
    const mean = stats.mean;
    const stdDev = stats.stdDev;

    if (count < this.minHistoryCount) {
      return {
        threshold: Number(fallbackThreshold),
        mean,
        stdDev
      };
    }

    const calculatedThreshold = mean + (numStdDevs * stdDev);
    const finalThreshold = Math.max(calculatedThreshold, fallbackThreshold);

    return {
      threshold: Number(finalThreshold),
      mean,
      stdDev
    };
  }

  clear() {
    this.statsMap.clear();
  }
}
