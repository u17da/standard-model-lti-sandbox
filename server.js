/**
 * 学習eポータル LTIテストシステム 統合ローカルサーバー
 */

const express = require('express');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 4000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 静的ファイルの提供 (UI)
app.use(express.static(path.join(__dirname, 'public')));

// Vercel ハンドラのラップ
const wrap = (handlerPath) => {
    return async (req, res) => {
        try {
            // ホットリロード対応（開発用）
            delete require.cache[require.resolve(handlerPath)];
            const handler = require(handlerPath);
            await handler(req, res);
        } catch (e) {
            console.error('[ServerError]', e);
            res.status(500).json({ error: 'Handler Error', message: e.message });
        }
    };
};

const platformPath = path.resolve(__dirname, 'api/platform.js');

// ルーティング
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public/index.html')));

// Platform API
app.use('/api/platform', wrap(platformPath));

const toolPath = path.resolve(__dirname, 'api/tool.js');
app.use('/api/tool', wrap(toolPath));



const server = app.listen(PORT, () => {
    console.log(`\n================================================`);
    console.log(`  学習eポータル LTIテストシステム 起動中`);
    console.log(`  URL: http://localhost:${PORT}`);
    console.log(`================================================\n`);
});

server.on('error', (e) => {
    console.error('[Server Error]', e);
});
