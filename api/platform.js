/**
 * 学習eポータル標準モデル V5.00 準拠 LTIプラットフォーム モック
 * (Generic Implementation for Verification)
 */

const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { db } = require('../src/firebase-admin');
const { TEST_USERS } = require('../src/users');

// LTI Hints Knowledge Base
const LTI_HINTS = {
    'MISSING_PROMPT': {
        title: 'prompt パラメータがありません',
        reason: '学習eポータル標準では、サイレントログインを実現するために prompt=none が必須です。',
        action: '認証リクエスト（Phase 2）のURLパラメータに `prompt=none` を追加してください。'
    },
    'WRONG_PROMPT': {
        title: 'prompt 値が正しくありません',
        reason: '学習eポータル標準では prompt は "none" 固定です。',
        action: '`prompt=login` や `consent` ではなく、必ず `prompt=none` を指定してください。'
    },
    'MISSING_CLIENT_ID': {
        title: 'Client ID がありません',
        reason: 'ツールを識別するための Client ID は必須です。',
        action: 'プラットフォーム画面に表示されている Client ID を指定してください。'
    },
    'MISSING_SCOPE': {
        title: 'scope が不適切です',
        reason: 'LTI 1.3 では scope=openid が必須です。',
        action: 'パラメータに `scope=openid` を含めてください。'
    },
    'WRONG_SCOPE': {
        title: 'scope 値が正しくありません',
        reason: 'LTI 1.3 認証リクエストでは scope は "openid" である必要があります。',
        action: '`scope=openid` を指定してください。'
    },
    'WRONG_RESPONSE_TYPE': {
        title: 'response_type が正しくありません',
        reason: 'LTI 1.3 では response_type=id_token が必須です。',
        action: '`response_type=id_token` を指定してください。'
    },
    'MISSING_NONCE': {
        title: 'nonce がありません',
        reason: 'リプレイ攻撃防止のため、ランダムな文字列（nonce）の送信が必須です。',
        action: 'ツール側でセッションごとにユニークな `nonce` を生成し設定してください。'
    },
    'MISSING_STATE': {
        title: 'state がありません',
        reason: 'セッション整合性を保つための state パラメータが必須です。',
        action: 'ツール側で生成した `state` パラメータを含めてください。'
    },
    'MISSING_LOGIN_HINT': {
        title: 'login_hint がありません',
        reason: 'LTI ログインフロー（OIDC Auth Response）では、ユーザーを特定するための login_hint が必須です。',
        action: 'ツール起動時に渡された `login_hint` をそのまま認証リクエストに含めてください。'
    },
    'MISSING_REDIRECT_URI': {
        title: 'redirect_uri がありません',
        reason: '認証完了後の戻り先（Launch URL）を指定する必要があります。',
        action: 'ツール側の起動エンドポイント（target_link_uri）を `redirect_uri` として指定してください。'
    },
    'MISSING_LTI_MESSAGE_HINT': {
        title: 'lti_message_hint がありません',
        reason: '学習eポータルとのセッション維持のために必須です。',
        action: 'ツール起動時に渡された `lti_message_hint` をそのまま認証リクエストに含めてください。'
    },
    'MISSING_RESPONSE_TYPE': {
        title: 'response_type がありません',
        reason: 'LTI 1.3 では response_type=id_token が必須です。',
        action: 'パラメータに `response_type=id_token` を含めてください。'
    },
    'MISSING_RESPONSE_MODE': {
        title: 'response_mode がありません',
        reason: 'まなびポケット等のポータルでは、セキュリティのため `form_post` 指定が必須です。',
        action: 'パラメータに `response_mode=form_post` を含めてください。'
    },
    'WRONG_RESPONSE_MODE': {
        title: 'response_mode が推奨値ではありません',
        reason: 'まなびポケット等多くのポータルでは `form_post` が推奨・必須です。',
        action: '`response_mode=form_post` を指定の上、POSTリクエストで受け取れるよう実装してください。'
    }
};

/**
 * LTI 1.3 パラメータ検証 (V5.00準拠)
 */
function validateLtiParams(params) {
    const results = [];
    const check = (key, expected, description, hintId) => {
        const val = params[key];
        if (!val) {
            results.push({
                key, level: 'ERROR',
                message: `必須 [${key}] がありません。`,
                detail: description,
                hintId: hintId || `MISSING_${key.toUpperCase()}`
            });
        } else if (expected && val !== expected) {
            results.push({
                key, level: 'WARNING',
                message: `[${key}] が推奨値 (${expected}) と異なります。`,
                detail: description,
                hintId: `WRONG_${key.toUpperCase()}`
            });
        } else {
            results.push({ key, level: 'SUCCESS', message: `OK: ${key}` });
        }
    };

    check('client_id', null, 'client_id が必要です。', 'MISSING_CLIENT_ID');
    check('login_hint', null, 'login_hint が必要です。');
    check('redirect_uri', null, 'redirect_uri (戻り先URL) が必要です。');
    check('lti_message_hint', null, 'lti_message_hint が必要です。');
    check('scope', 'openid', 'scope=openid は必須です。', 'MISSING_SCOPE');
    check('response_type', 'id_token', 'response_type=id_token である必要があります。');
    check('prompt', 'none', 'prompt=none である必要があります。', 'MISSING_PROMPT');
    check('nonce', null, 'セキュリティのため nonce は必須です。', 'MISSING_NONCE');
    check('state', null, '整合性確認のため state は必須です。', 'MISSING_STATE');
    check('response_mode', 'form_post', 'form_post 形式での応答が推奨されます。', 'WRONG_RESPONSE_MODE');

    return results;
}

// 鍵の読み込み
const keyDir = path.resolve(__dirname, '../keys');

// 1. Priority: Environment Variables (for Vercel/Production)
// Process escaped newlines (\n) if present in the env var
const PRIVATE_KEY = process.env.LTI_PRIVATE_KEY
    ? process.env.LTI_PRIVATE_KEY.replace(/\\n/g, '\n')
    : (fs.existsSync(path.join(keyDir, 'private.pem'))
        ? fs.readFileSync(path.join(keyDir, 'private.pem'), 'utf8')
        : null);

const PUBLIC_KEY = process.env.LTI_PUBLIC_KEY
    ? process.env.LTI_PUBLIC_KEY.replace(/\\n/g, '\n')
    : (fs.existsSync(path.join(keyDir, 'public.pem'))
        ? fs.readFileSync(path.join(keyDir, 'public.pem'), 'utf8')
        : null);

// DB Helper: Log
async function logToDb(phase, message, data, level, sessionId = null) {
    try {
        await db.collection('logs').add({
            phase, message, data, level,
            sessionId,
            timestamp: new Date().toISOString()
        });
    } catch (e) {
        console.error('Log Write Error:', e);
    }
}

// DB Helper: Get Logs
async function getLogsFromDb(sessionId = null) {
    try {
        // Fetch more logs to ensure we find the session even in busy environments
        // Ordering by timestamp desc is built-in for single-field queries in Firestore
        const snapshot = await db.collection('logs')
            .orderBy('timestamp', 'desc')
            .limit(500)
            .get();

        let logs = snapshot.docs.map(doc => doc.data());
        const totalFetched = logs.length;

        if (sessionId && sessionId !== 'null' && sessionId !== 'undefined') {
            logs = logs.filter(l => l.sessionId === sessionId);
        }

        // Return in chronological order
        return {
            logs: logs.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp)),
            debug: { sessionId, totalFetched, matchedCount: logs.length }
        };
    } catch (e) {
        console.error('Log Read Error:', e);
        return { logs: [], error: e.message };
    }
}

// 共通ヘッダー設定
function setCommonHeaders(res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Cache-Control', 'no-store');
}

module.exports = async (req, res) => {
    const { method, url } = req;
    const parsedUrl = new URL(url, `http://${req.headers.host}`);
    const pathname = parsedUrl.pathname;

    // CORS & Cache Setting
    setCommonHeaders(res);

    // Response Helpers
    res.status = (code) => { res.statusCode = code; return res; };
    res.json = (data) => {
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify(data));
    };
    res.send = (data) => {
        if (typeof data === 'object') return res.json(data);
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.end(data);
    };
    res.redirect = (url) => {
        res.statusCode = 302;
        res.setHeader('Location', url);
        res.end();
    };

    try {
        // Structural Route Resolution
        const base = '/api/platform';
        let subpath = pathname.startsWith(base) ? pathname.slice(base.length) : pathname;
        subpath = subpath.replace(/\/$/, '') || '/';

        // Additional normalization for Vercel
        if (subpath.startsWith('/api/')) subpath = subpath.slice(4);
        if (!subpath.startsWith('/')) subpath = '/' + subpath;

        const routeKey = `${method}:${subpath}`;

        switch (routeKey) {
            case 'GET:/':
                return res.send('Platform API Ready');

            case 'POST:/initiate':
                return handleInitiate(req, res);

            case 'GET:/oauth/authorize':
            case 'POST:/oauth/authorize':
                return handleAuthorize(req, res, parsedUrl);

            case 'GET:/jwks':
                return handleJwks(req, res);

            case 'POST:/token':
                return res.json({ access_token: 'valid-mock-token', token_type: 'Bearer', expires_in: 3600 });

            case 'POST:/check-jwks':
                return handleCheckJwks(req, res);

            case 'GET:/logs':
                const sessionId = parsedUrl.searchParams.get('sessionId') || parsedUrl.searchParams.get('session_id');
                const logData = await getLogsFromDb(sessionId);
                return res.json(logData);

            case 'POST:/issue-certificate':
                return await handleIssueCertificate(req, res);

            case 'GET:/certificate':
            case 'POST:/certificate':
                return await handleCertificate(req, res, parsedUrl);

            case 'GET:/certificate/verify':
                return await handleCertificateVerify(req, res, parsedUrl);

            default:
                return res.status(404).json({
                    error: 'Endpoint Not Found',
                    path: pathname,
                    subpath: subpath,
                    method: method
                });
        }
    } catch (e) {
        console.error('[Platform] HANDLER ERROR:', e);
        if (!res.headersSent) res.status(500).json({ error: 'Internal Server Error', debug: e.message });
    }
};

async function handleInitiate(req, res) {
    const { initiation_url, client_id, target_link_uri, login_hint: user_id, session_id, break_prompt, break_scope } = req.body;
    const final_iss = 'https://standard-eportal-v5.example.com';
    const final_client_id = client_id || 'standard-test-client';

    // 匿名起動の判定
    const isAnonymous = user_id === 'anonymous';
    const login_hint = isAnonymous ? 'anonymous-hint' : user.id;
    const deployment_id = isAnonymous ? 'S_999999999999' : `S_${user.school_code}`;

    const params = new URLSearchParams({
        iss: final_iss,
        login_hint: login_hint,
        target_link_uri: target_link_uri,
        lti_message_hint: JSON.stringify({ user_id: user.id, session_id }),
        lti_deployment_id: deployment_id,
        client_id: final_client_id,
        scope: break_scope ? 'invalid_scope' : 'openid'
    });

    if (!break_prompt) {
        params.set('prompt', 'none');
    }

    await logToDb('PHASE_1_INIT', 'Platform -> Tool: OIDC Initiation Sent', {
        endpoint: initiation_url,
        params: Object.fromEntries(params)
    }, 'INFO', session_id);

    return res.send(`
        <html>
        <body onload="document.forms[0].submit()">
            <form action="${initiation_url}" method="POST">
                ${Array.from(params.entries()).map(([k, v]) => `<input type="hidden" name="${k}" value='${v}'>`).join('')}
            </form>
            <p>Redirecting to Tool (Standard LTI Launch)...</p>
        </body>
        </html>
    `);
}

async function handleAuthorize(req, res, parsedUrl) {
    const params = { ...Object.fromEntries(parsedUrl.searchParams), ...req.body };
    const { state, redirect_uri, nonce, login_hint, lti_message_hint } = params;

    // Extract session_id from lti_message_hint if possible
    let session_id = null;
    try {
        if (lti_message_hint) {
            const hint = JSON.parse(lti_message_hint);
            session_id = hint.session_id;
        }
    } catch (e) { }

    // パラメータ検証
    const validationResults = validateLtiParams(params);
    const hasCriticalError = validationResults.some(r => r.level === 'ERROR');

    await logToDb('PHASE_2_AUTH_REQUEST', 'Tool -> Platform: 認証要求を受け取りました。パラメータを検証中...', {
        received_params: params,
        validation_results: validationResults
    }, hasCriticalError ? 'ERROR' : (validationResults.some(r => r.level === 'WARNING') ? 'WARNING' : 'INFO'), session_id);

    if (hasCriticalError) {
        return res.status(400).send(`
            <div style="font-family: sans-serif; padding: 2rem; color: #EF4444; background: #FEF2F2; border: 1px solid #FECACA; border-radius: 8px; margin: 2rem;">
                <h2 style="margin-top:0;">LTI 起動エラー: 仕様不適合</h2>
                <p>LTI仕様に準拠していない、または必須パラメータが欠落しているリクエストを検知したため、セキュリティ保護のため起動を中断しました。</p>
                <p>元の画面のログに表示されている「解決策のヒント」を確認して修正してください。</p>
                <hr style="border:0; border-top:1px solid #FECACA; margin: 1.5rem 0;">
                <div style="font-size:0.9rem;">
                    <strong>エラー項目:</strong>
                    <ul style="margin-top:0.5rem;">
                        ${validationResults.filter(r => r.level === 'ERROR').map(r => `<li>[${r.key}] ${r.message}</li>`).join('')}
                    </ul>
                </div>
            </div>
        `);
    }

    // ユーザー特定
    const isAnonymous = login_hint === 'anonymous-hint';
    const user = isAnonymous ? null : (TEST_USERS.find(u => u.id === login_hint) || TEST_USERS[0]);

    const now = Math.floor(Date.now() / 1000);
    const payload = {
        iss: 'https://standard-eportal-v5.example.com',
        sub: isAnonymous ? 'anonymous-subject' : user.sub, // 匿名時は固定IDまたは除外を検討（ここでは固定IDとする）
        aud: params.client_id,
        iat: now,
        exp: now + 3600,
        nonce: nonce,
        'https://purl.imsglobal.org/spec/lti/claim/message_type': 'LtiResourceLinkRequest',
        'https://purl.imsglobal.org/spec/lti/claim/version': '1.3.0',
        'https://purl.imsglobal.org/spec/lti/claim/deployment_id': isAnonymous ? 'S_999999999999' : `S_${user.school_code}`,
        'https://purl.imsglobal.org/spec/lti/claim/target_link_uri': redirect_uri,
        'https://purl.imsglobal.org/spec/lti/claim/resource_link': { id: 'resource-' + (isAnonymous ? 'anonymous' : user.sub) },
        'https://purl.imsglobal.org/spec/lti/claim/roles': isAnonymous
            ? ['http://purl.imsglobal.org/vocab/lis/v2/institution/person#Guest']
            : [user.role],
        'https://purl.imsglobal.org/spec/lti/claim/context': {
            id: isAnonymous ? 'ctx-anonymous' : 'ctx-' + user.school_code,
            label: 'STANDARD-CLASS',
            title: isAnonymous ? 'Anonymous Course' : 'Standard Verification Course',
            type: ['CourseSection']
        }
    };

    // 匿名でない場合のみ追加情報を付加
    if (!isAnonymous) {
        payload.name = user.name;
        payload['https://purl.imsglobal.org/spec/lti/claim/custom'] = {
            applic_grades: user.grade || ''
        };
    }

    try {
        if (!PRIVATE_KEY) throw new Error('Private Key not loaded');
        const idToken = jwt.sign(payload, PRIVATE_KEY, { algorithm: 'RS256', keyid: 'key-1' });

        await logToDb('PHASE_3_LAUNCH', 'Platform -> Tool: LTI Launch (ID Token Issued)', {
            sub: payload.sub,
            roles: payload['https://purl.imsglobal.org/spec/lti/claim/roles'],
            target: redirect_uri,
            client_id: params.client_id
        }, 'SUCCESS', session_id);

        return res.send(`
            <!DOCTYPE html>
            <html>
            <body onload="document.forms[0].submit()">
                <form method="POST" action="${redirect_uri}">
                    <input type="hidden" name="id_token" value="${idToken}"/>
                    <input type="hidden" name="state" value="${state}"/>
                </form>
            </body>
            </html>
        `);
    } catch (e) {
        console.error('Sign Error', e);
        await logToDb('ERROR', 'Token Generation Failed', { error: e.message }, 'ERROR');
        return res.status(500).send('Internal Server Error: ' + e.message);
    }
}

function handleJwks(req, res) {
    if (!PUBLIC_KEY) {
        return res.status(500).json({ error: 'Public Key not available' });
    }
    try {
        const publicKey = crypto.createPublicKey(PUBLIC_KEY);
        const jwk = publicKey.export({ format: 'jwk' });
        res.json({
            keys: [{
                ...jwk,
                kid: 'key-1',
                use: 'sig',
                alg: 'RS256'
            }]
        });
    } catch (e) {
        console.error('JWK Export Error:', e);
        res.status(500).json({ error: 'Failed to export JWK' });
    }
}

async function handleCheckJwks(req, res) {
    const { jwks_uri } = req.body;
    if (!jwks_uri) return res.status(400).json({ success: false, message: 'JWKS URI missing' });

    try {
        const response = await fetch(jwks_uri);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        if (!data.keys || !Array.isArray(data.keys)) throw new Error('Invalid JWKS format (keys not found)');

        return res.json({
            success: true,
            message: 'JWKS Valid',
            detail: `Found ${data.keys.length} keys.`
        });
    } catch (e) {
        return res.json({
            success: false,
            message: 'Connection Failed',
            detail: e.message
        });
    }
}

/**
 * 証明書トークンの生成 (Platform側)
 */
async function handleIssueCertificate(req, res) {
    const { user_id, client_id, tool_url, tool_name } = req.body;
    const user = TEST_USERS.find(u => u.id === user_id) || TEST_USERS[0];

    try {
        if (!PRIVATE_KEY) throw new Error('Private Key not loaded');

        const certPayload = {
            iss: 'https://standard-eportal-v5.example.com',
            sub: 'lti-interop-proof-' + Date.now(),
            platform_name: tool_name || 'サンプルツール',
            school_name: user.school_name || 'Standard School',
            client_id: client_id || 'standard-test-client',
            target_link_uri: tool_url || 'unknown',
            deployment_id: `S_${user.school_code}`,
            lti_version: '1.3.0',
            standard_version: 'V5.00',
            iat: Math.floor(Date.now() / 1000),
            jti: 'cert-' + Math.random().toString(36).substr(2, 9)
        };

        const certToken = jwt.sign(certPayload, PRIVATE_KEY, { algorithm: 'RS256' });

        // 短縮IDの生成とキャッシュ保存 (感度向上のための短縮URL用)
        const shortId = Math.random().toString(36).substr(2, 8).toUpperCase();
        await db.collection('certificates').doc(shortId).set({
            token: certToken,
            created_at: new Date().toISOString()
        });

        // Resolve platform verify URL dynamically
        const protocol = req.headers['x-forwarded-proto'] || 'http';
        const host = req.headers.host;
        const platformVerifyUrl = `${protocol}://${host}/api/platform/certificate`;
        return res.redirect(`${platformVerifyUrl}?id=${shortId}`);

    } catch (e) {
        console.error('Cert Issue Error', e);
        return res.status(500).send('Certificate generation failed: ' + e.message);
    }
}

/**
 * 証明書表示画面 (Platform Hosting)
 */
async function handleCertificate(req, res, parsedUrl) {
    const shortId = parsedUrl.searchParams.get('id');
    let token = parsedUrl.searchParams.get('token');

    const protocol = req.headers['x-forwarded-proto'] || 'http';
    const host = req.headers.host;

    if (!token && shortId) {
        const doc = await db.collection('certificates').doc(shortId).get();
        if (doc.exists) token = doc.data().token;
    }

    if (!token) return res.status(400).send('Certificate not found or expired');

    try {
        const decoded = jwt.verify(token, PUBLIC_KEY, { algorithms: ['RS256'] });

        // QRコード用のURL (IDがあればID優先で極限まで短くする)
        const verifyUrl = shortId
            ? `${protocol}://${host}/api/platform/certificate/verify?id=${shortId}`
            : `${protocol}://${host}/api/platform/certificate/verify?token=${token}`;

        res.send(`
            <!DOCTYPE html>
            <html lang="ja">
            <head>
                <meta charset="UTF-8">
                <title>LTI Interoperability Certificate</title>
                <script src="https://cdnjs.cloudflare.com/ajax/libs/qrious/4.0.2/qrious.min.js"></script>
                <style>
                    :root { 
                        --connect-orange: #F39800; 
                        --gold: #D4AF37; 
                        --mp-blue: #009fe8;
                        --mp-blue-hover: #0087c5;
                    }
                    body { 
                        background: #FDFCF0; 
                        font-family: "Helvetica Neue", Arial, "Hiragino Kaku Gothic ProN", "Hiragino Sans", Meiryo, sans-serif; 
                        display: flex; 
                        flex-direction: column;
                        align-items: center; 
                        min-height: 100vh; 
                        margin: 0; 
                        padding: 40px 20px;
                        box-sizing: border-box;
                    }
                    .actions {
                        width: 800px;
                        display: flex;
                        justify-content: flex-end;
                        margin-bottom: 20px;
                    }
                    .btn-download {
                        background: var(--mp-blue);
                        color: white !important;
                        text-decoration: none;
                        padding: 10px 24px;
                        border-radius: 999px;
                        font-weight: bold;
                        font-size: 0.95rem;
                        box-shadow: 0 4px 12px rgba(0, 159, 232, 0.3);
                        transition: all 0.2s;
                        border: none;
                        cursor: pointer;
                        display: flex;
                        align-items: center;
                        gap: 8px;
                    }
                    .btn-download:hover {
                        background: var(--mp-blue-hover);
                        transform: translateY(-1px);
                        box-shadow: 0 6px 16px rgba(0, 159, 232, 0.4);
                    }
                    .btn-download:active {
                        transform: translateY(0);
                    }
                    .certificate-frame { 
                        background: white; 
                        width: 800px; 
                        padding: 40px; 
                        border: 15px double var(--gold); 
                        box-shadow: 0 10px 30px rgba(0,0,0,0.1); 
                        position: relative; 
                        text-align: center; 
                        box-sizing: border-box;
                    }
                    .certificate-inner { border: 2px solid var(--gold); padding: 40px; height: 100%; position: relative; }
                    .certificate-inner::before { content: 'CERTIFICATE'; position: absolute; top: 0; left: 0; right: 0; font-size: 6rem; color: rgba(212, 175, 55, 0.05); letter-spacing: 0.5rem; pointer-events: none; }
                    h1 { font-size: 3.5rem; color: var(--gold); margin: 0; font-family: serif; letter-spacing: 2px; text-transform: uppercase; }
                    .subtitle { font-size: 1.2rem; border-top: 2px solid #333; border-bottom: 2px solid #333; display: inline-block; padding: 5px 20px; margin: 10px 0 30px; font-weight: bold; }
                    .recipient-name { font-size: 2.2rem; font-weight: bold; margin: 20px 0; border-bottom: 1px solid #ddd; display: inline-block; min-width: 60%; padding-bottom: 5px; }
                    .body-text { font-size: 1.1rem; line-height: 1.8; color: #333; margin: 20px 0; }
                    .meta { margin-top: 40px; display: flex; justify-content: space-between; align-items: flex-end; }
                    .qr-container { text-align: left; }
                    canvas { border: 4px solid white; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
                    .qr-label { font-size: 0.75rem; color: #666; margin-bottom: 5px; font-weight: bold; }
                    .signature { text-align: right; border-top: 1px solid #333; padding-top: 10px; min-width: 200px; }
                    .sig-label { font-size: 1rem; font-style: italic; font-family: serif; }
                    .sig-date { font-size: 0.9rem; color: #666; margin-top: 5px; }

                    @media print {
                        body { background: white; padding: 0; width: 210mm; height: 297mm; display: block; }
                        .actions { display: none; }
                        .certificate-frame { 
                            box-shadow: none; 
                            border-width: 10mm; 
                            width: 190mm; 
                            margin: 10mm auto;
                            -webkit-print-color-adjust: exact;
                        }
                        .certificate-inner { border-width: 1pt; }
                    }
                </style>
            </head>
            <body>
                <div class="actions">
                    <button class="btn-download" onclick="window.print()">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
                        証明書をダウンロード (PDF)
                    </button>
                </div>

                <div class="certificate-frame">
                    <div class="certificate-inner">
                        <h1>Certificate</h1>
                        <div class="subtitle">of LTI 1.3 Interoperability</div>
                        
                        <div class="body-text">
                            This is to certify that a successful connection has been established<br>
                            between the LTI Platform and the LTI Tool.
                        </div>
                        
                        <div class="recipient-name" style="font-size: 1.8rem;">${decoded.platform_name || 'LTI Platform'}</div>
                        
                        <div class="body-text">
                            verified technical interoperability for <strong>${decoded.school_name}</strong><br>
                            in accordance with the <strong>Learning e-Portal Standard ${decoded.standard_version}</strong>.
                        </div>

                        <div style="margin: 20px 0; text-align: left; background: #f9fafb; padding: 15px; border-radius: 8px; border: 1px solid #eee; font-family: monospace; font-size: 0.85rem; display: inline-block; min-width: 80%;">
                            <div style="margin-bottom: 5px;"><strong>Target Link URI:</strong> ${decoded.target_link_uri}</div>
                            <div style="margin-bottom: 5px;"><strong>Client ID:</strong> ${decoded.client_id}</div>
                            <div><strong>Deployment ID:</strong> ${decoded.deployment_id}</div>
                        </div>

                        <div class="meta">
                            <div class="qr-container">
                                <div class="qr-label">Verify Authenticity</div>
                                <canvas id="qr"></canvas>
                            </div>
                            <div class="signature">
                                <div class="sig-label">LTI Platform Provider</div>
                                <div class="sig-date">Date: ${new Date(decoded.iat * 1000).toLocaleDateString('ja-JP')}</div>
                            </div>
                        </div>
                    </div>
                </div>
                <script>
                    new QRious({
                        element: document.getElementById('qr'),
                        value: '${verifyUrl}',
                        size: 180,
                        level: 'L'
                    });
                </script>
            </body>
            </html>
        `);
    } catch (e) {
        res.status(401).send('Invalid certificate token: ' + e.message);
    }
}

/**
 * 証明書検証エンドポイント (Platform Hosting)
 */
async function handleCertificateVerify(req, res, parsedUrl) {
    const shortId = parsedUrl.searchParams.get('id');
    let token = parsedUrl.searchParams.get('token');

    if (!token && shortId) {
        const doc = await db.collection('certificates').doc(shortId).get();
        if (doc.exists) token = doc.data().token;
    }

    const styleValid = 'background: #ecfdf5; border: 2px solid #10b981; color: #064e3b;';
    const styleInvalid = 'background: #fef2f2; border: 2px solid #ef4444; color: #7f1d1d;';

    let statusClass = '';
    let title = '';
    let content = '';
    let decoded = null;

    try {
        if (!token) throw new Error(shortId ? 'Certificate ID expired or invalid' : 'Token missing');
        decoded = jwt.verify(token, PUBLIC_KEY, { algorithms: ['RS256'] });

        statusClass = styleValid;
        title = '✅ Valid Interoperability Proof';
        content = `
            <div class="field">
                <label>LTI Platform</label>
                <div class="value">${decoded.platform_name}</div>
            </div>
            <div class="field">
                <label>Institution</label>
                <div class="value">${decoded.school_name}</div>
            </div>
            <div class="field">
                <label>Standard Compliance</label>
                <div class="value">LTI 1.3 / Standard ${decoded.standard_version}</div>
            </div>
            <div class="field">
                <label>Technical Details</label>
                <div class="value" style="font-family: monospace; font-size: 0.8rem;">
                    Target Link URI: ${decoded.target_link_uri}<br>
                    Client ID: ${decoded.client_id}<br>
                    Deploy ID: ${decoded.deployment_id}
                </div>
            </div>
            <div class="field">
                <label>Verification Date</label>
                <div class="value">${new Date().toLocaleString()}</div>
            </div>
        `;

        // JSON response for M2M verification
        if (req.headers.accept && req.headers.accept.includes('application/json')) {
            return res.json({
                valid: true,
                data: {
                    platform: decoded.platform_name,
                    school: decoded.school_name,
                    client_id: decoded.client_id,
                    target_link_uri: decoded.target_link_uri,
                    deployment_id: decoded.deployment_id,
                    issued_at: new Date(decoded.iat * 1000).toISOString()
                }
            });
        }
    } catch (e) {
        statusClass = styleInvalid;
        title = '❌ Invalid Certificate';
        content = `
            <p>The certificate token is invalid, expired, or tampered with.</p>
            <p class="error-detail">Error: ${e.message}</p>
        `;
        if (req.headers.accept && req.headers.accept.includes('application/json')) {
            return res.status(401).json({ valid: false, error: e.message });
        }
    }

    res.send(`
        <!DOCTYPE html>
        <html lang="ja">
        <head>
            <meta charset="UTF-8">
            <title>Certificate Verification</title>
            <style>
                body { font-family: sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; background: #f3f4f6; }
                .result-card { background: white; width: 90%; max-width: 500px; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
                .status-header { padding: 20px; text-align: center; font-weight: bold; font-size: 1.2rem; ${statusClass} }
                .result-body { padding: 30px; }
                .field { margin-bottom: 20px; border-bottom: 1px solid #f3f4f6; padding-bottom: 10px; }
                .field:last-child { border-bottom: none; }
                label { display: block; font-size: 0.8rem; color: #6b7280; margin-bottom: 5px; }
                .value { font-size: 1.1rem; color: #1f2937; font-weight: 500; }
                .error-detail { color: #dc2626; font-size: 0.9rem; margin-top: 10px; }
                .footer { text-align: center; padding: 20px; background: #f9fafb; font-size: 0.8rem; color: #9ca3af; }
            </style>
        </head>
        <body>
            <div class="result-card">
                <div class="status-header">${title}</div>
                <div class="result-body">
                    ${content}
                </div>
                <div class="footer">
                    Authorized Verification Service<br>
                    (Mock Learning e-Portal Platform)
                </div>
            </div>
        </body>
        </html>
    `);
}
