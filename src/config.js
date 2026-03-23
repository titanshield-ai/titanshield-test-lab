// ═══════════════════════════════════════════════════════════════════════════
// 🧪 TitanShield Test Lab — config.js
//
// Tests: Feature 5 (Secret Entropy + HIBP Cross-Reference)
//
// Intentional vulnerabilities:
//   CWE-798: Hardcoded credentials (AWS key, Stripe, JWT secret, DB password)
// ═══════════════════════════════════════════════════════════════════════════

// ── Hardcoded AWS credentials ─────────────────────────────────────────────
// TitanShield will detect this pattern AND check HaveIBeenPwned
const AWS_ACCESS_KEY = "AKIA_TEST_TITANSHIELD_DEMO_KEY_XYZ";  // pattern: AKIA + 16 chars
const AWS_SECRET = "test/TITANSHIELD+DemoSecretKey+ForScan+Lab0001=";

// ── Hardcoded Stripe-style secret key ─────────────────────────────────────
// High-entropy string assigned to 'secret' variable — entropy scanner catches this
const STRIPE_KEY = "sk_test_TitanShieldDemoKeyForSecurityScanning123456";

// ── Hardcoded JWT secret (high-entropy → entropy scanner will flag) ───────
const JWT_SECRET = "mySuperSecretJWTKey_TitanShield_abc123xyz789qwerty";

// ── Hardcoded database password ───────────────────────────────────────────
const DB_CONFIG = {
    host: "db.internal.company.com",
    user: "admin",
    password: "TitanShield@TestPassword2024!",
    database: "production_db"
};

// ── Hardcoded Google API Key (pattern: AIza + 35 chars) ───────────────────
const GOOGLE_KEY = "AIza_TitanShield_TestKey_ForSecurityScanDemo_1234";

module.exports = { AWS_ACCESS_KEY, AWS_SECRET, STRIPE_KEY, JWT_SECRET, DB_CONFIG, GOOGLE_KEY };

