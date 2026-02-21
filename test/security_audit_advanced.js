const fs = require('fs');
const http = require('http');

const BASE_URL = 'http://localhost:4000/api/platform';
const LOG_FILE = 'audit_result.log';

function log(msg, ...args) {
    const text = msg + (args.length ? ' ' + args.map(a => JSON.stringify(a)).join(' ') : '');
    console.log(text);
    fs.appendFileSync(LOG_FILE, text + '\n');
}

async function runAdvancedTests() {
    fs.writeFileSync(LOG_FILE, ''); // Clear log
    log('Starting Advanced Security Audit (Red Team Mode)...\n');
    let failures = 0;

    // 1. SSRF Advanced Bypasses
    log('[AUDIT 1] SSRF Denylist Bypasses (check-jwks)');
    const ssrfPayloads = [
        'http://127.1/',          // Shortened Loopback
        'http://0.0.0.0/',        // Any Interface
        'http://0x7f000001/',     // Hex IP
        'http://0177.0.0.1/',     // Octal IP
        'http://[::1]/',          // IPv6 Loopback
        'http://localhost.localdomain/' // Alt hostname
    ];

    for (const payload of ssrfPayloads) {
        try {
            const res = await fetch(`${BASE_URL}/check-jwks`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ jwks_uri: payload })
            });
            const data = await res.json();

            // "Connection Failed" usually means it tried to fetch but failed (DNS/Network),
            // verifying that the BLOCK didn't happen BEFORE the fetch.
            // We want it to be BLOCKED (Invalid URL / Security Violation).
            if (data.success === false && data.message.includes('Invalid URL')) {
                log(`  PASS: Blocked ${payload}`);
            } else if (data.message === 'Connection Failed') {
                // If it attempted connection, it failed the filter!
                log(`  FAIL: Filter Bypassed! Tried to fetch ${payload}`);
                failures++;
            } else {
                log(`  FAIL: Unexpected result for ${payload}`, data);
                failures++;
            }
        } catch (e) {
            log(`  ERROR testing ${payload}:`, e.message);
            failures++;
        }
    }

    // 2. Host Header Injection
    log('\n[AUDIT 2] Host Header Injection (Certificate Issue)');
    try {
        const res = await fetch(`${BASE_URL}/issue-certificate`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Host': 'evil.com' // Inject malicious host
            },
            body: JSON.stringify({
                user_id: 'student1', // Assuming ID exists
                client_id: 'client1'
            }),
            redirect: 'manual'
        });

        if (res.status === 302) {
            const location = res.headers.get('location');
            if (location && location.includes('evil.com')) {
                log('  FAIL: Poisoned Location Header found: ' + location);
                failures++;
            } else if (location) {
                log('  PASS: Location header uses trusted host (or request failed safe): ' + location);
            }
        } else if (res.status === 400 || res.status === 403) {
            log('  PASS: Request rejected due to invalid Host header (Status: ' + res.status + ')');
        } else {
            log('  INFO: Request rejected or not redirected (Status: ' + res.status + ')');
            // 400/500 is acceptable if it rejects the host mismatch
        }

    } catch (e) {
        log('  ERROR:', e.message);
    }

    log('\n------------------------------------------------');
    if (failures === 0) {
        log('Audit Result: ✅ NO WEAKNESSES FOUND');
    } else {
        log(`Audit Result: ⚠️ ${failures} POTENTIAL WEAKNESSES FOUND`);
    }
}

runAdvancedTests();
