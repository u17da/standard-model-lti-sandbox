
const http = require('http');

const BASE_URL = 'http://localhost:4000/api/platform';

async function runTests() {
    console.log('Starting Security Verification Tests...\n');
    let failures = 0;

    // 1. SSRF Check
    console.log('[TEST 1] SSRF Protection (check-jwks)');
    try {
        const res = await fetch(`${BASE_URL}/check-jwks`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ jwks_uri: 'http://169.254.169.254/latest/meta-data/' })
        });
        const data = await res.json();
        if (data.success === false && (data.message.includes('Invalid URL') || data.detail.includes('blocked'))) {
            console.log('  PASS: Request to metadata server was blocked.');
        } else {
            console.log('  FAIL: Request was not strictly blocked.', data);
            failures++;
        }
    } catch (e) {
        console.log('  ERROR:', e.message);
        failures++;
    }

    // 2. Open Redirect Check
    console.log('\n[TEST 2] Open Redirect Protection (authorize)');
    try {
        // javascript: scheme should be blocked by "http/https" check
        const params = new URLSearchParams({
            client_id: 'standard-test-client',
            redirect_uri: 'javascript:alert(1)',
            response_type: 'id_token',
            scope: 'openid',
            nonce: 'n',
            state: 's',
            login_hint: 'user1'
        });
        const res = await fetch(`${BASE_URL}/oauth/authorize?${params}`);
        const text = await res.text();

        if (res.status === 400 && text.includes('redirect_uri')) {
            console.log('  PASS: Malicious redirect_uri was rejected.');
        } else {
            console.log('  FAIL: Malicious redirect_uri was accepted or different error.', res.status);
            failures++;
        }
    } catch (e) {
        console.log('  ERROR:', e.message);
        failures++;
    }

    // 3. XSS Check
    console.log('\n[TEST 3] XSS Protection (Certificate)');
    try {
        // Issue certificate with XSS payload
        const xssPayload = '<script>alert("XSS")</script>';
        const issueRes = await fetch(`${BASE_URL}/issue-certificate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                user_id: 'student1',
                client_id: 'client1',
                tool_url: 'http://tool.com',
                tool_name: xssPayload
            }),
            redirect: 'manual'
        });

        if (issueRes.status === 302) {
            const certUrl = issueRes.headers.get('location');
            const viewRes = await fetch(certUrl);
            const html = await viewRes.text();

            if (html.includes('&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;') && !html.includes(xssPayload)) {
                console.log('  PASS: XSS payload was correctly escaped in HTML.');
            } else {
                console.log('  FAIL: XSS payload was found unescaped!');
                failures++;
            }
        } else {
            console.log('  FAIL: Certificate issuance did not redirect.', issueRes.status);
            failures++;
        }

    } catch (e) {
        console.log('  ERROR:', e.message);
        failures++;
    }

    // 4. Info Leakage Check (Logs)
    console.log('\n[TEST 4] Information Leakage (Logs)');
    try {
        const resNoSession = await fetch(`${BASE_URL}/logs`);
        const dataNoSession = await resNoSession.json();

        if (dataNoSession.error === 'ACCESS_DENIED') {
            console.log('  PASS: Log access without session ID was denied.');
        } else {
            console.log('  FAIL: Log access allowed without session ID.', dataNoSession);
            failures++;
        }

        // Check with session ID (should be allowed)
        const resWithSession = await fetch(`${BASE_URL}/logs?sessionId=test-session`);
        const dataWithSession = await resWithSession.json();
        if (Array.isArray(dataWithSession.logs)) {
            console.log('  PASS: Log access with session ID was allowed.');
        } else {
            console.log('  FAIL: Log access with session ID failed.', dataWithSession);
            failures++;
        }

    } catch (e) {
        console.log('  ERROR:', e.message);
        failures++;
    }

    console.log('\n------------------------------------------------');
    if (failures === 0) {
        console.log('Global Result: ✅ ALL CHECKS PASSED');
    } else {
        console.log(`Global Result: ❌ ${failures} CHECKS FAILED`);
    }
}

// Check if server is up, if not wait a bit (manual start required or we assume it's running)
// For this script, we assume the agent started it.
runTests();
