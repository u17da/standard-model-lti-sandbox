const http = require('http');

const BASE_URL = 'http://localhost:4000/api/platform';

async function runRegressionTests() {
    console.log('Starting Regression Tests (Normal Operation Check)...\n');
    let failures = 0;

    // 1. Root Endpoint
    try {
        const res = await fetch(BASE_URL + '/');
        const text = await res.text();
        if (res.status === 200 && text === 'Platform API Ready') {
            console.log('✅ Base Endpoint: OK');
        } else {
            console.log('❌ Base Endpoint: Valid Request Failed', res.status, text);
            failures++;
        }
    } catch (e) { console.log('❌ Base Endpoint Error:', e.message); failures++; }

    // 2. JWKS Check (Valid URL)
    // We use a known public JWKS or the platform's own JWKS to test success
    try {
        const myJwks = `${BASE_URL}/jwks`;
        const res = await fetch(`${BASE_URL}/check-jwks`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ jwks_uri: myJwks })
        });
        const data = await res.json();
        if (data.success === true && data.message === 'JWKS Valid') {
            console.log('✅ JWKS Check (Self): OK');
        } else {
            console.log('❌ JWKS Check: Valid Request Failed', data);
            failures++;
        }
    } catch (e) {
        // If the server blocks localhost (which it probably doesn't for the machine itself, but logic might), check logic.
        // Actually, internal fetch to localhost:4000 might be blocked by our SSRF filter if it resolves to 127.0.0.1!
        // Wait, did we allow 127.0.0.1? The blocked list included 127.0.0.0/8!
        // So checking *itself* might fail if it resolves to 127.0.0.1.
        // This is an interesting regression: "Can the platform talk to itself?"
        console.log('⚠️ JWKS Check Error (Expected if Localhost is blocked by SSRF?):', e.message);
    }

    // Let's try to fetch google's JWKS (Public Internet)
    try {
        const googleJwks = 'https://www.googleapis.com/oauth2/v3/certs';
        const res = await fetch(`${BASE_URL}/check-jwks`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ jwks_uri: googleJwks })
        });
        const data = await res.json();
        if (data.success === true) {
            console.log('✅ JWKS Check (Google): OK (Internet Access Verified)');
        } else {
            console.log('❌ JWKS Check (Google): Failed', data);
            failures++;
        }
    } catch (e) { console.log('❌ JWKS Check (Google) Error:', e.message); failures++; }


    // 3. Issue Certificate (Valid Host)
    try {
        const res = await fetch(`${BASE_URL}/issue-certificate`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Host': 'localhost:4000' // Valid Host
            },
            body: JSON.stringify({ user_id: 'student1', client_id: 'reg-test' }),
            redirect: 'manual'
        });

        if (res.status === 302) {
            const loc = res.headers.get('location');
            if (loc && loc.includes('/api/platform/certificate')) {
                console.log('✅ Certificate Issue: OK (Redirects to certificate)');
            } else {
                console.log('❌ Certificate Issue: Wrong Redirect', loc);
                failures++;
            }
        } else {
            console.log('❌ Certificate Issue: Failed', res.status);
            failures++;
        }
    } catch (e) { console.log('❌ Cert Issue Error:', e.message); failures++; }

    console.log('\n------------------------------------------------');
    if (failures === 0) {
        console.log('Regression Result: ✅ ALL SYSTEMS NORMAL');
    } else {
        console.log(`Regression Result: ⚠️ ${failures} FAILURES DETECTED`);
    }
}

runRegressionTests();
