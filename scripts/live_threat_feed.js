/**
 * Interactive Live Threat Detector CLI Tool
 * Feed live login events dynamically and inspect the real-time sliding window stores & risk scores.
 */

import readline from 'readline';
import { CredentialStuffingDetector } from '../src/security/credential_stuffing/credentialStuffingDetector.js';

const detector = new CredentialStuffingDetector();

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

console.log('================================================================');
console.log('       LIVE CREDENTIAL STUFFING DETECTOR INTERACTIVE CLI       ');
console.log('================================================================');
console.log('Type a quick command to feed live events into the detector engine:\n');
console.log('  1. "fail <ip> <user>"           -> Record a failed login from IP for user');
console.log('  2. "succ <ip> <user>"           -> Record a successful login from IP for user');
console.log('  3. "spray <ip> <count>"         -> Spray <count> failed logins from <ip> across distinct users');
console.log('  4. "bot <ip> <user> <ua_name>"  -> Record a login with specific bot User-Agent (e.g. python-requests)');
console.log('  5. "pwspray <hash> <count>"     -> Attempt same password hash across <count> users');
console.log('  6. "exit"                       -> Exit live CLI\n');

function promptUser() {
  rl.question('live-detector> ', (line) => {
    const parts = line.trim().split(/\s+/);
    const cmd = parts[0]?.toLowerCase();

    if (cmd === 'exit' || cmd === 'quit') {
      console.log('Exiting live threat detector CLI.');
      rl.close();
      return;
    }

    if (cmd === 'fail') {
      const ip = parts[1] || '192.168.1.50';
      const user = parts[2] || 'USER_101';
      const event = {
        event_id: `EVT_LIVE_${Date.now()}`,
        event_type: 'login',
        entity_id: user,
        ip_address: ip,
        timestamp: new Date(),
        payload: { login_success: false, user_agent: 'Mozilla/5.0 Chrome/126.0' }
      };
      const res = detector.detect(event);
      printResult(res);
    } else if (cmd === 'succ') {
      const ip = parts[1] || '192.168.1.50';
      const user = parts[2] || 'USER_101';
      const event = {
        event_id: `EVT_LIVE_${Date.now()}`,
        event_type: 'login',
        entity_id: user,
        ip_address: ip,
        timestamp: new Date(),
        payload: { login_success: true, user_agent: 'Mozilla/5.0 Chrome/126.0' }
      };
      const res = detector.detect(event);
      printResult(res);
    } else if (cmd === 'spray') {
      const ip = parts[1] || '198.51.100.10';
      const count = parseInt(parts[2] || '5', 10);
      console.log(`Sending ${count} live spray events from IP ${ip}...`);
      let lastRes = null;
      for (let i = 1; i <= count; i++) {
        lastRes = detector.detect({
          event_id: `EVT_SPRAY_${i}_${Date.now()}`,
          event_type: 'login',
          entity_id: `SPRAY_USER_${i}`,
          ip_address: ip,
          timestamp: new Date(),
          payload: { login_success: false, user_agent: 'Mozilla/5.0 Chrome/126.0' }
        });
      }
      printResult(lastRes);
    } else if (cmd === 'bot') {
      const ip = parts[1] || '198.51.100.22';
      const user = parts[2] || 'USER_BOT';
      const ua = parts[3] || 'python-requests/2.28.0';
      const event = {
        event_id: `EVT_BOT_${Date.now()}`,
        event_type: 'login',
        entity_id: user,
        ip_address: ip,
        timestamp: new Date(),
        payload: { login_success: false, user_agent: ua }
      };
      const res = detector.detect(event);
      printResult(res);
    } else if (cmd === 'pwspray') {
      const hash = parts[1] || 'super_secret_hash_999';
      const count = parseInt(parts[2] || '6', 10);
      console.log(`Spraying password hash '${hash}' across ${count} distinct users...`);
      let lastRes = null;
      for (let i = 1; i <= count; i++) {
        lastRes = detector.detect({
          event_id: `EVT_PW_${i}_${Date.now()}`,
          event_type: 'login',
          entity_id: `TARGET_ACC_${i}`,
          ip_address: `203.0.113.${10 + (i % 5)}`,
          timestamp: new Date(),
          payload: { login_success: false, password_hash: hash, user_agent: 'Mozilla/5.0 Chrome/126.0' }
        });
      }
      printResult(lastRes);
    } else if (cmd) {
      console.log(`Unknown command '${cmd}'. Try: fail, succ, spray, bot, pwspray, exit`);
    }

    promptUser();
  });
}

function printResult(res) {
  console.log('\n--- LIVE DETECTOR RESULT ---');
  console.log(`Total Threat Score: ${res.score} / 100`);
  console.log(`Fired Rules Count:  ${res.evidence_metadata.rules_fired_count || 0}`);
  if (res.reasons && res.reasons.length > 0) {
    console.log('Triggered Reasons:');
    res.reasons.forEach(r => console.log(` - ${r}`));
  } else {
    console.log('Triggered Reasons: None (Normal Traffic)');
  }
  console.log('Evidence Metadata:', JSON.stringify(res.evidence_metadata, null, 2));
  console.log('----------------------------\n');
}

promptUser();
