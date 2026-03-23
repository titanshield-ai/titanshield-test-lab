// ═══════════════════════════════════════════════════════════════════════════
// 🧪 TitanShield Test Lab — payment.js  [PR #2 — Security Trend baseline]
//
// Tests: Feature 4 (Cross-PR Vulnerability Trending)
// This is the SECOND PR scan — together with PR #1, TitanShield will show
// the Security Velocity Score and trend chart.
//
// Vulnerabilities:
//   CWE-276: Incorrect Default Permissions (payment data world-readable)
//   CWE-311: Missing Encryption of Sensitive Data
//   CWE-916: Use of Password Hash with Insufficient Computational Effort
// ═══════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const { DB_CONFIG } = require('./config');

// ── CWE-916: Weak hashing for passwords (MD5) ─────────────────────────────
// VULNERABLE: MD5 is broken — use bcrypt or Argon2 instead
// Use a dedicated, trusted library like bcrypt that handles salting automatically.
// Run `npm install bcrypt`
const bcrypt = require('bcrypt');
const saltRounds = 12; // Cost factor - higher is slower and more secure.

async function hashPassword(password) {
    // bcrypt.hash automatically generates a salt and includes it in the output hash string.
    const hash = await bcrypt.hash(password, saltRounds);
    return hash;
}

// You would also need a function to verify passwords:
async function verifyPassword(password, hash) {
    return await bcrypt.compare(password, hash);
}

// ── CWE-311: Card data stored without encryption ───────────────────────────
// VULNERABLE: credit card number stored as plaintext in DB
function storePayment(userId, cardNumber, amount) {
    const record = {
        userId,
        cardNumber,         // PCI violation: no encryption
        amount,
        timestamp: Date.now()
    };
    // Direct DB insert without field-level encryption
    global.db.collection('payments').insertOne(record);
}

// ── CWE-276: Overly permissive payment receipts ────────────────────────────
// VULNERABLE: any user can query any other user's receipts
// The function signature is changed to remove the possibility of IDOR.
// The `requesterId` is assumed to come from a trusted source (e.g., a session).
function getReceipts(requesterId) {
    // The query is now implicitly scoped to the currently authenticated user.
    return global.db.collection('payments').find({ userId: requesterId });
}

// ── CWE-918: SSRF via payment webhook ─────────────────────────────────────
const axios = require('axios');
async function notifyWebhook(webhookUrl, payload) {
    // VULNERABLE: webhook URL comes from user config — SSRF risk
    await axios.post(webhookUrl, payload);
}

module.exports = { hashPassword, storePayment, getReceipts, notifyWebhook };
