/**
 * 検証用 LTI Tool モック (APIハンドラ)
 * PlatformからのLaunchを受け、内容を表示するだけの簡易実装
 */

const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

// 鍵の読み込み (Tool固有の鍵が理想だが、テスト環境の共通鍵を使用)
const keyDir = path.resolve(__dirname, '../keys');

const TOOL_PRIVATE_KEY = process.env.LTI_PRIVATE_KEY
    ? process.env.LTI_PRIVATE_KEY.replace(/\\n/g, '\n')
    : (fs.existsSync(path.join(keyDir, 'private.pem'))
        ? fs.readFileSync(path.join(keyDir, 'private.pem'), 'utf8')
        : null);

const TOOL_PUBLIC_KEY = process.env.LTI_PUBLIC_KEY
    ? process.env.LTI_PUBLIC_KEY.replace(/\\n/g, '\n')
    : (fs.existsSync(path.join(keyDir, 'public.pem'))
        ? fs.readFileSync(path.join(keyDir, 'public.pem'), 'utf8')
        : null);

module.exports = async (req, res) => {
    const { method, url } = req;
    const parsedUrl = new URL(url, `http://${req.headers.host}`);
    const pathname = parsedUrl.pathname;

    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Cache-Control', 'no-store');

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
        if (method === 'POST' && pathname.endsWith('/initiate')) {
            return await handleToolInitiate(req, res);
        }
        if (method === 'POST' && pathname.endsWith('/launch')) {
            return await handleToolLaunch(req, res);
        }


        // Default / Status Page
        if (method === 'GET' && (pathname === '/' || pathname === '' || pathname === '/api/tool')) {
            return res.send(`
                <!DOCTYPE html>
                <html lang="ja">
                <head>
                    <meta charset="UTF-8">
                    <title>LTI Tool - Standby</title>
                    <style>
                        body { font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: #f0f9ff; color: #075985; }
                        .card { padding: 2rem; background: white; border-radius: 16px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); text-align: center; }
                        .spinner { width: 40px; height: 40px; border: 4px solid #e0f2fe; border-top: 4px solid #0ea5e9; border-radius: 50%; animation: spin 1s linear infinite; margin: 0 auto 1.5rem; }
                        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
                    </style>
                </head>
                <body>
                    <div class="card">
                        <div class="spinner"></div>
                        <h2>LTI Tool: Standby</h2>
                        <p>Platfromからの起動待機中...</p>
                    </div>
                </body>
                </html>
            `);
        }

        return res.status(404).json({ error: 'Tool Endpoint Not Found', path: pathname });
    } catch (e) {
        console.error('[Tool Error]', e);
        return res.status(500).json({ error: 'Internal Tool Error', message: e.message });
    }
};

/**
 * Step 1: Login Initiation 受け取り -> Step 2: Authentication Request リダイレクト
 */
async function handleToolInitiate(req, res) {
    const { iss, login_hint, target_link_uri, lti_message_hint } = req.body;

    // Resolve Platform Auth URL dynamically based on the current host
    const protocol = req.headers['x-forwarded-proto'] || 'http';
    const host = req.headers.host;
    const platformAuthUrl = `${protocol}://${host}/api/platform/oauth/authorize`;

    const params = new URLSearchParams({
        response_type: 'id_token',
        scope: req.body.scope || 'openid',
        response_mode: 'form_post',
        client_id: req.body.client_id || 'standard-test-client',
        redirect_uri: target_link_uri,
        login_hint: login_hint,
        lti_message_hint: lti_message_hint,
        state: 'random-state-' + Date.now(),
        nonce: 'random-nonce-' + Date.now()
    });

    if (req.body.prompt) {
        params.set('prompt', req.body.prompt);
    }

    // リダイレクト (Auto Submit Form for POST recommended by LTI, but GET redirect is also often supported. 
    // Platform implementation supports POST/GET. Using GET redirect for simplicity here)
    res.redirect(`${platformAuthUrl}?${params.toString()}`);
}

/**
 * Step 3: Launch (ID Token) 受け取り -> 検証結果表示
 */
async function handleToolLaunch(req, res) {
    const { id_token, state } = req.body;

    if (!id_token) {
        return res.status(400).send('Error: Missing id_token');
    }

    // ID Token のデコード
    const decoded = jwt.decode(id_token, { complete: true });
    const claims = decoded.payload;

    // 表示用データの抽出
    const roleList = claims['https://purl.imsglobal.org/spec/lti/claim/roles'] || [];
    let roleLabel = '不明';
    if (roleList.some(r => r.includes('Instructor') || r.includes('Faculty'))) roleLabel = '教員';
    else if (roleList.some(r => r.includes('Learner') || r.includes('Student'))) roleLabel = '児童生徒';

    const custom = claims['https://purl.imsglobal.org/spec/lti/claim/custom'] || {};
    const grade = custom.applic_grades || '(未設定)';
    const deployId = claims['https://purl.imsglobal.org/spec/lti/claim/deployment_id'] || '-';
    const userName = claims.name || 'No Name';

    // 結果表示画面 (Standard V5 Style - ICT CONNECT 21 Theme)
    res.send(`
        <!DOCTYPE html>
        <html lang="ja">
        <head>
            <meta charset="UTF-8">
            <title>LTI Launch Verification</title>
            <link href="https://fonts.googleapis.com/css2?family=Noto+Sans+JP:wght@400;500;700&family=Fira+Code:wght@400&display=swap" rel="stylesheet">
            <style>
                :root {
                    /* ICT CONNECT 21 Colors */
                    --ict-blue: #005BAC;
                    --connect-orange: #F39800;
                    --bg-body: #F9FAFB;
                    --bg-card: #FFFFFF;
                    --text-main: #333333;
                    --text-muted: #666666;
                    --border: #E5E7EB;
                    --success: #10b981;
                }
                body { margin: 0; font-family: 'Noto Sans JP', sans-serif; background: var(--bg-body); color: var(--text-main); display: flex; justify-content: center; min-height: 100vh; padding: 2rem; box-sizing: border-box; }
                .container { width: 100%; max-width: 900px; background: var(--bg-card); border-radius: 8px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06); overflow: hidden; display: flex; flex-direction: column; border: 1px solid var(--border); }
                
                .header { background: #FFFFFF; padding: 2rem; text-align: center; border-bottom: 3px solid var(--ict-blue); }
                h1 { margin: 0; font-size: 1.8rem; color: var(--ict-blue); font-weight: 700; }
                .badge { display: inline-block; background: #ECFDF5; color: var(--success); padding: 4px 16px; border-radius: 9999px; font-size: 0.9rem; margin-top: 0.8rem; border: 1px solid #D1FAE5; font-weight: 600; }

                .content { padding: 2rem; }
                .info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1.5rem; margin-bottom: 2rem; background: #F3F4F6; padding: 1.5rem; border-radius: 8px; border: 1px solid var(--border); }
                .info-item { display: flex; flex-direction: column; }
                .info-label { font-size: 0.85rem; color: var(--text-muted); margin-bottom: 0.4rem; font-weight: 600; }
                .info-value { font-size: 1.1rem; font-weight: 700; color: var(--text-main); }

                .tabs { display: flex; gap: 1rem; border-bottom: 2px solid var(--border); margin-bottom: 1.5rem; }
                .tab-btn { background: none; border: none; color: var(--text-muted); padding: 0.8rem 1rem; cursor: pointer; font-family: inherit; font-weight: 600; position: relative; transition: color 0.2s; font-size: 1rem; }
                .tab-btn:hover { color: var(--ict-blue); }
                .tab-btn.active { color: var(--ict-blue); }
                .tab-btn.active::after { content: ''; position: absolute; bottom: -2px; left: 0; width: 100%; height: 2px; background: var(--ict-blue); }

                .tab-content { display: none; animation: fadeIn 0.3s ease; }
                .tab-content.active { display: block; }
                @keyframes fadeIn { from { opacity: 0; transform: translateY(5px); } to { opacity: 1; transform: translateY(0); } }

                table { width: 100%; border-collapse: collapse; font-size: 0.95rem; }
                th { text-align: left; padding: 1rem; color: var(--text-muted); border-bottom: 1px solid var(--border); width: 30%; background: #F9FAFB; font-weight: 600; }
                td { padding: 1rem; border-bottom: 1px solid var(--border); word-break: break-all; color: var(--text-main); }
                tr:last-child th, tr:last-child td { border-bottom: none; }

                pre { background: #1F2937; padding: 1.5rem; border-radius: 8px; overflow-x: auto; margin: 0; font-family: 'Fira Code', monospace; font-size: 0.85rem; border: 1px solid #374151; color: #E5E7EB; }

                .btn-return { display: block; width: 100%; text-align: center; padding: 1rem; background: #FFFFFF; color: var(--ict-blue); text-decoration: none; border-radius: 6px; margin-top: 2rem; border: 1px solid var(--ict-blue); transition: all 0.2s; font-weight: 700; }
                .btn-return:hover { background: #F0F9FF; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>LTI Launch Successful!</h1>
                    <div class="badge">✓ Authentication Verified</div>
                </div>
                
                <div class="content">
                    <div class="info-grid">
                        <div class="info-item"><span class="info-label">Name</span><span class="info-value">${userName}</span></div>
                        <div class="info-item"><span class="info-label">Role</span><span class="info-value">${roleLabel}</span></div>
                        <div class="info-item"><span class="info-label">Grade (Custom)</span><span class="info-value">${grade}</span></div>
                        <div class="info-item"><span class="info-label">Deployment ID</span><span class="info-value">${deployId}</span></div>
                    </div>

                    <div class="tabs">
                        <button class="tab-btn active" onclick="switchTab('formatted')">Formatted Claims</button>
                        <button class="tab-btn" onclick="switchTab('raw')">Raw JSON</button>
                    </div>

                    <div id="formatted" class="tab-content active">
                        <table>
                            <tr><th>Subject (sub)</th><td>${claims.sub}</td></tr>
                            <tr><th>Issuer (iss)</th><td>${claims.iss}</td></tr>
                            <tr><th>Audience (aud)</th><td>${claims.aud}</td></tr>
                            <tr><th>Context</th><td>${claims['https://purl.imsglobal.org/spec/lti/claim/context'] ? claims['https://purl.imsglobal.org/spec/lti/claim/context'].label : '-'}</td></tr>
                            <tr><th>LTI Version</th><td>${claims['https://purl.imsglobal.org/spec/lti/claim/version']}</td></tr>
                        </table>
                    </div>

                    <div id="raw" class="tab-content">
                        <pre>${JSON.stringify(claims, null, 2)}</pre>
                    </div>

                </div>
            </div>

            <script>
                function switchTab(id) {
                    document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
                    document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
                    document.getElementById(id).classList.add('active');
                    event.target.classList.add('active');
                }
            </script>
        </body>
        </html>
    `);
}


