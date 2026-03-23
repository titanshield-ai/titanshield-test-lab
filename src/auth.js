// ═══════════════════════════════════════════════════════════════════════════
// 🧪 TitanShield Test Lab — auth.js
//
// Tests: Feature 1 (Blast Radius — auth is called by payment, admin, search)
//        Feature 2 (Attack Simulation PoC)
//
// Intentional vulnerabilities:
//   CWE-287: Improper Authentication (JWT verification disabled)
//   CWE-284: Broken Access Control (no role check on admin endpoints)
//   CWE-613: Insufficient Session Expiration
// ═══════════════════════════════════════════════════════════════════════════

const jwt = require('jsonwebtoken');
const { JWT_SECRET } = require('./config');

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

// ── Blast Radius target: these functions are called by:
//    - src/payment.js:processPayment()  → handles credit card data
//    - src/api.js:adminRoute()          → manages all users
//    - src/search.js:searchUsers()      → queries all user records
// Any bug here exposes ALL THREE downstream endpoints.
module.exports = { verifyToken, isAuthorized, createSession };
