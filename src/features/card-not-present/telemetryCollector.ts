/**
 * Cybersecurity Telemetry Collector for CNP Transactions
 * Collects runtime browser metrics and simulates environment security signals.
 */

import { CNPTelemetry } from './types/cnpTypes.js';

export class TelemetryCollector {
  /**
   * Generates or captures telemetry data with optional scenario overrides
   */
  public collectTelemetry(overrideData?: Partial<CNPTelemetry>): CNPTelemetry {
    const now = new Date();
    const loginTimeStr = new Date(now.getTime() - 1000 * 60 * 12).toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit',
      hour12: true
    });

    // Default Browser Inspection Metrics
    const userAgent = typeof navigator !== 'undefined' ? navigator.userAgent : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36';
    const browser = this.parseBrowser(userAgent);
    const os = this.parseOS(userAgent);

    const defaultTelemetry: CNPTelemetry = {
      deviceStatus: 'Known Device',
      deviceFingerprint: `FP-${Math.random().toString(36).substring(2, 9).toUpperCase()}-2026`,
      browser,
      os,
      rootedJailbroken: false,

      currentCity: 'Mumbai, IN',
      previousCity: 'Mumbai, IN',
      impossibleTravel: false,
      ipAddress: '49.207.210.45',
      vpnDetected: false,
      proxyDetected: false,
      networkType: 'Wi-Fi',
      wifiCategory: 'Home WiFi',

      loginTime: loginTimeStr,
      sessionDurationSeconds: 720, // 12 minutes
      failedLoginAttempts: 0,
      otpAttempts: 1,
      biometricUsed: true
    };

    return {
      ...defaultTelemetry,
      ...overrideData
    };
  }

  private parseBrowser(ua: string): string {
    if (ua.includes('Chrome')) return 'Chrome 122.0';
    if (ua.includes('Firefox')) return 'Firefox 123.0';
    if (ua.includes('Safari')) return 'Safari 17.2';
    if (ua.includes('Edge')) return 'Edge 122.0';
    return 'Chrome 122.0';
  }

  private parseOS(ua: string): string {
    if (ua.includes('Windows')) return 'Windows 11 Pro';
    if (ua.includes('Mac')) return 'macOS Sonoma';
    if (ua.includes('Android')) return 'Android 14';
    if (ua.includes('iPhone') || ua.includes('iPad')) return 'iOS 17.3';
    return 'Windows 11 Pro';
  }
}

export const telemetryCollector = new TelemetryCollector();
