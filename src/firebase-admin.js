const admin = require('firebase-admin');
const fs = require('fs');
const path = require('path');

// Initialize Firebase Admin with environment awareness
function initializeFirebase() {
    if (admin.apps.length > 0) return admin.apps[0];

    try {
        // 1. Priority: Individual Environment Variables (Structural fix for Vercel/Production)
        if (process.env.FIREBASE_PROJECT_ID && process.env.FIREBASE_CLIENT_EMAIL && process.env.FIREBASE_PRIVATE_KEY) {
            console.log('[Firebase] Initializing from individual environment variables');
            return admin.initializeApp({
                credential: admin.credential.cert({
                    projectId: process.env.FIREBASE_PROJECT_ID,
                    clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
                    // Replace escaped newlines if they are passed as literal '\n' strings
                    privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
                })
            });
        }

        // 2. Legacy Priority: JSON Environment Variable
        if (process.env.FIREBASE_SERVICE_ACCOUNT) {
            console.log('[Firebase] Initializing from FIREBASE_SERVICE_ACCOUNT env var');
            const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
            return admin.initializeApp({
                credential: admin.credential.cert(serviceAccount)
            });
        }

        // 3. Fallback: Local File (For local development consistency)
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
