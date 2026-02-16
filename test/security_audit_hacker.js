const fs = require('fs');
const http = require('http');

const BASE_URL = 'http://localhost:4000/api/platform';
const LOG_FILE = 'audit_hacker.log';

function log(msg, ...args) {
    const text = msg + (args.length ? ' ' + args.map(a => JSON.stringify(a)).join(' ') : '');
    console.log(text);
    fs.appendFileSync(LOG_FILE, text + '\n');
}

async function runHackerTests() {
    fs.writeFileSync(LOG_FILE, '');
    log('Starting Hacker-Level Security Audit (Black Box / Static Analysis verification)...\n');
    let failures = 0;

    // 1. Error Message Leakage
    // Intentionally send malformed JSON to trigger 500/400 and check if stack traces or internal paths leak.
    log('[AUDIT 3] Information Leakage via Error Messages');
    try {
        const res = await fetch(`${BASE_URL}/check-jwks`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: 'INVALID_JSON_{'
        });
        const text = await res.text();
        // Express default error handler might return HTML with stack trace in development
        if (text.includes('SyntaxError') && (text.includes('node_modules') || text.includes('c:\\Users'))) {
            log('  FAIL: Stack trace or internal path leaked in JSON parse error.');
            log('  Preview:', text.substring(0, 100));
            failures++;
        } else {
            log('  PASS: No stack trace leaked on malformed JSON.');
        }

        // Trigger internal logic error (missing key handled by try-catch?)
        // The current implementation is robust, but let's try injecting a weird type
        const res2 = await fetch(`${BASE_URL}/issue-certificate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ user_id: { "$ne": null } }) // NoSQL Injection probe
        });
        const text2 = await res2.text();
        if (text2.includes('Error') && (text2.includes('Object') || text2.includes('prototype'))) {
            log('  WARN: Potential implementation details leaked in logic error:', text2.substring(0, 100));
        } else {
            log('  PASS: Logic error handled gracefully.');
        }

    } catch (e) {
        log('  ERROR:', e.message);
    }

    // 2. DoS: Large Payload
    log('\n[AUDIT 4] DoS - Large Payload Handling');
    try {
        const bigString = 'A'.repeat(1024 * 1024 * 5); // 5MB
        const res = await fetch(`${BASE_URL}/check-jwks`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ jwks_uri: 'http://example.com', huge_field: bigString })
        });

        if (res.status === 413) {
            log('  PASS: Large payload rejected (413 Payload Too Large).');
        } else if (res.status === 200 || res.status === 400 || res.status === 500) {
            // If it returns 200, it processed 5MB. Express default limit is usually 100kb.
            // If explicit limit not set, it might be vulnerable.
            log(`  WARN: Server accepted 5MB payload (Status: ${res.status}). Check body-parser limits.`);
            failures++;
        } else {
            log(`  INFO: Server response status: ${res.status}`);
        }
    } catch (e) {
        log('  ERROR (DoS Test):', e.message);
    }

    // 3. DNS Rebinding (Logic Check Simulation)
    // Since we cannot easily setup a custom DNS server here, we rely on the findings from code review.
    // The vulnerability is: validateUrlWithDns() -> fetch()
    // This is a known TOCTOU.
    log('\n[AUDIT 5] DNS Rebinding Vulnerability Check (Static Analysis)');
    log('  CRITICAL FAIL: Code Logic Vulnerable to TOCTOU (Time-of-Check Time-of-Use)');
    log('  Reason: `validateUrlWithDns` resolves IP, checks it, then `fetch` resolves it AGAIN.');
    log('  Exploit: Attacker sets short DNS TTL. 1st resolve = Safe IP. 2nd resolve = 127.0.0.1.');
    failures++;

    log('\n------------------------------------------------');
    if (failures === 0) {
        log('Hacker Audit Result: ✅ NO TRIVIAL WEAKNESSES (But fix DNS Rebinding!)');
    } else {
        log(`Hacker Audit Result: ☠️ ${failures} VULNERABILITIES FOUND`);
    }
}

runHackerTests();
