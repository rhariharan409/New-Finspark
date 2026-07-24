/**
 * Live E2E Blocking Verification Script
 * Spins up the Express server locally, performs real HTTP requests,
 * and verifies that credential stuffing threat scores trigger real 403 blocks.
 */

import http from 'http';
import { spawn } from 'child_process';
import assert from 'assert';

console.log('================================================================');
console.log('      STARTING LIVE E2E AUTHENTICATION BLOCKING VERIFICATION    ');
console.log('================================================================\n');

// 1. Spin up the Express server on a custom port to avoid collisions
const port = 3333;
const serverProcess = spawn('node', ['server.js'], {
  stdio: 'pipe',
  env: { ...process.env, PORT: String(port) }
});

let serverOutput = '';
serverProcess.stdout.on('data', (data) => {
  serverOutput += data.toString();
});

serverProcess.stderr.on('data', (data) => {
  console.error('[Server Error]', data.toString());
});

// Wait for server to start
await new Promise((resolve) => {
  const checkInterval = setInterval(() => {
    if (serverOutput.includes('Bank of Turtles Server running')) {
      clearInterval(checkInterval);
      resolve();
    }
  }, 100);
});

console.log(`✓ Express server is running on port ${port}.\n`);

const email = `test_user_${Date.now()}@turtle.com`;
const username = `test_user_${Date.now()}`;
const password = 'SuperSecurePassword123!';
const testIp = '198.51.100.111';

// Helper to make JSON POST request
function makePostRequest(path, body) {
  return new Promise((resolve, reject) => {
    const postData = JSON.stringify(body);
    const req = http.request({
      hostname: 'localhost',
      port: port,
      path: path,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData),
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0.0.0'
      }
    }, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body: JSON.parse(data || '{}')
        });
      });
    });

    req.on('error', (err) => reject(err));
    req.write(postData);
    req.end();
  });
}

try {
  // STEP 1: Create a test user via signup
  console.log('STEP 1: Registering test user via POST /api/auth/signup...');
  const signupResponse = await makePostRequest('/api/auth/signup', {
    email,
    username,
    password,
    confirmPassword: password,
    fullName: 'E2E Test User'
  });
  console.log('Signup Response Status:', signupResponse.statusCode);
  console.log('Signup Response Body:', JSON.stringify(signupResponse.body, null, 2));
  assert.equal(signupResponse.statusCode, 201, 'Signup should succeed');

  // STEP 2: Log in successfully with correct password
  console.log('\nSTEP 2: Logging in successfully with correct password...');
  const loginSuccessResponse = await makePostRequest('/api/auth/login', {
    identifier: email,
    password: password,
    ipAddress: testIp
  });
  console.log('Success Login Response Status:', loginSuccessResponse.statusCode);
  console.log('Success Login Response Body:', JSON.stringify(loginSuccessResponse.body, null, 2));
  assert.equal(loginSuccessResponse.statusCode, 200, 'Login with correct credentials should succeed');

  // STEP 3: Send sequential requests with wrong password from same IP
  console.log('\nSTEP 3: Sending sequential login requests with WRONG password from IP:', testIp);
  let attempts = 0;
  let response = null;
  let blockedAtAttempt = null;

  for (let i = 1; i <= 10; i++) {
    response = await makePostRequest('/api/auth/login', {
      identifier: email,
      password: 'wrong_password_here',
      ipAddress: testIp
    });
    
    console.log(`Attempt ${i}: Status = ${response.statusCode}, Message = "${response.body.message}"`);

    if (response.statusCode === 403) {
      blockedAtAttempt = i;
      break;
    }
  }

  console.log(`\nResult: Blocked at Attempt #${blockedAtAttempt}`);
  console.log('Blocked Response Payload:', JSON.stringify(response.body, null, 2));
  
  assert.ok(blockedAtAttempt !== null, 'Should have blocked the attempts');
  assert.equal(response.statusCode, 403, 'Should return 403 Forbidden on block');
  assert.equal(response.body.message, 'Access blocked due to suspicious activity.', 'Should contain blocked message');

  // STEP 4: Confirm scope of the block by changing the IP address
  const newTestIp = '198.51.100.222';
  console.log('\nSTEP 4: Confirming scope - Changing IP address to:', newTestIp);
  const differentIpResponse = await makePostRequest('/api/auth/login', {
    identifier: email,
    password: 'wrong_password_here',
    ipAddress: newTestIp
  });

  console.log(`Attempt from new IP ${newTestIp}: Status = ${differentIpResponse.statusCode}, Message = "${differentIpResponse.body.message}"`);
  assert.equal(differentIpResponse.statusCode, 401, 'Should return 401 (Invalid password) instead of 403 Blocked, confirming IP isolation');
  console.log('✓ Verified: Block is scoped correctly to IP address/identifier combination.');

  console.log('\n================================================================');
  console.log('      ALL LIVE E2E AUTHENTICATION BLOCKING VERIFICATIONS PASSED! ');
  console.log('================================================================\n');

} catch (err) {
  console.error('\n❌ Verification Failed:', err);
  process.exitCode = 1;
} finally {
  serverProcess.kill();
}
