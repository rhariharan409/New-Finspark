/**
 * Detector Registry (Person 2: SK)
 * Central registry pattern for auto-discovering threat detector plugins.
 */

class Registry {
  constructor() {
    this.detectorsMap = new Map();
  }

  register(detectorInstance) {
    if (!detectorInstance || !detectorInstance.detectorName) {
      throw new Error('Detector instance must possess a valid detectorName property.');
    }
    this.detectorsMap.set(detectorInstance.detectorName, detectorInstance);
    console.log(`[Registry] Registered threat detector: ${detectorInstance.detectorName}`);
  }

  get(detectorName) {
    return this.detectorsMap.get(detectorName);
  }

  getAll() {
    return Array.from(this.detectorsMap.values());
  }

  clear() {
    this.detectorsMap.clear();
  }
}

export const DetectorRegistry = new Registry();
