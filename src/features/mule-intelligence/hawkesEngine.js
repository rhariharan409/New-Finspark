/**
 * Hawkes Engine
 * Implements a decaying-intensity approximation of a Hawkes process for receiver inflow activity.
 */

/**
 * Updates Hawkes intensity with a new inflow event.
 * @param {number} prevIntensity 
 * @param {number} prevTimestampMs 
 * @param {number} nowMs 
 * @param {number} alpha Spike intensity (default 0.6)
 * @param {number} beta Decay rate (default 0.15)
 * @returns {number}
 */
export function updateHawkesIntensity(prevIntensity, prevTimestampMs, nowMs, alpha = 0.6, beta = 0.15) {
  const dtSeconds = Math.max(0, (nowMs - prevTimestampMs) / 1000);
  const decayed = prevIntensity * Math.exp(-beta * dtSeconds);
  return decayed + alpha;
}

/**
 * Decays Hawkes intensity when no events have occurred.
 * @param {number} prevIntensity 
 * @param {number} prevTimestampMs 
 * @param {number} nowMs 
 * @param {number} beta Decay rate (default 0.15)
 * @returns {number}
 */
export function decayHawkesIntensity(prevIntensity, prevTimestampMs, nowMs, beta = 0.15) {
  const dtSeconds = Math.max(0, (nowMs - prevTimestampMs) / 1000);
  return prevIntensity * Math.exp(-beta * dtSeconds);
}
