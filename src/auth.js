// ═══════════════════════════════════════════════════════════════════════════
// 🧪 TitanShield Test Lab — auth.js  [UPDATED for Blast Radius Test]
//
// Tests: Feature 1 (Blast Radius — auth is called by payment, admin, search)
//
// NEW in this commit: added explicit downstream call graph comments and
// a new verifyAdmin() function that exposes 4 downstream endpoints.
// ═══════════════════════════════════════════════════════════════════════════

const jwt = require('jsonwebtoken');
const { JWT_SECRET, PAYMENT_CONFIG } = require('./config');

// ── CWE-287: JWT verification disabled ───────────────────────────────────
// VULNERABLE: algorithms: ['none'] allows unsigned tokens to pass
function verifyToken(token) {
    return jwt.verify(token, JWT_SECRET, { algorithms: ['none', 'HS256'] });
}

// ── CWE-284: No role-based access control ─────────────────────────────────
// VULNERABLE: no check that user has admin role before granting access
function isAuthorized(user, resource) {
    if (user && user.id) {
        return true;  // any logged-in user can access anything
    }
    return false;
}

// ── CWE-613: Session never expires ───────────────────────────────────────
// VULNERABLE: token issued with no expiry
function createSession(userId) {
    return jwt.sign({ id: userId, role: 'user' }, JWT_SECRET);
    // MISSING: expiresIn: '1h'
}

// ── NEW: verifyAdmin — called by 4 downstream critical endpoints ───────────
// BLAST RADIUS TARGET: a bypass here exposes all 4 callers simultaneously.
// Callers (downstream endpoints this function gates):
//   1. POST /api/admin/users         → manages ALL user accounts
//   2. DELETE /api/admin/users/:id   → deletes user data (GDPR risk)
//   3. GET /api/admin/payments       → reads ALL payment records (PCI risk)
//   4. POST /api/admin/config        → changes system configuration
function verifyAdmin(token) {
    try {
        const decoded = verifyToken(token);   // <-- calls the vulnerable verifyToken above
        // BUG: role is never checked — any valid token (including 'none' algorithm) passes
        return decoded !== null;
    } catch (e) {
        return false;
    }
}

// ── NEW: Payment auth — uses Braintree private key from config ────────────
// CWE-798: Hardcoded credential pulled from config into auth flow
function initPaymentGateway() {
    const braintree = require('braintree');
    return new braintree.BraintreeGateway({
        environment: braintree.Environment.Production,
        merchantId: PAYMENT_CONFIG.merchantId,
        publicKey: PAYMENT_CONFIG.publicKey,
        privateKey: PAYMENT_CONFIG.privateKey,   // hardcoded private key
    });
}

// ── Call graph for TitanShield Blast Radius analysis ─────────────────────
// verifyToken() ──→ isAuthorized() ──→ [payments, admin users, config, reports]
// verifyAdmin()  ──→ verifyToken() ──→ [admin CRUD — highest risk]
module.exports = { verifyToken, isAuthorized, createSession, verifyAdmin, initPaymentGateway };
