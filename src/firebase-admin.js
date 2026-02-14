const admin = require('firebase-admin');
const fs = require('fs');
const path = require('path');

// Initialize Firebase Admin with environment awareness
function initializeFirebase() {
    if (admin.apps.length > 0) return admin.apps[0];

    try {
        // 1. Priority: Environment Variable (Structural fix for Vercel/Production)
        if (process.env.FIREBASE_SERVICE_ACCOUNT) {
            console.log('[Firebase] Initializing from environment variable');
            const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
            return admin.initializeApp({
                credential: admin.credential.cert(serviceAccount)
            });
        }

        // 2. Fallback: Local File (For local development consistency)
        const filePath = path.resolve(__dirname, '../service-account.json');
        if (fs.existsSync(filePath)) {
            console.log('[Firebase] Initializing from local service-account.json');
            const serviceAccount = require(filePath);
            return admin.initializeApp({
                credential: admin.credential.cert(serviceAccount)
            });
        }

        throw new Error('No Firebase configuration found (env var or file)');
    } catch (error) {
        console.error('[Firebase] Initialization Error:', error.message);
        throw error;
    }
}

const app = initializeFirebase();
const db = app.firestore();

module.exports = { admin, db };
