// ═══════════════════════════════════════════════════════════════════════════
// 🧪 TitanShield Test Lab — config.js  [UPDATED for HIBP + Entropy Test]
//
// Tests: Feature 5 (Secret Entropy + HIBP Cross-Reference)
//
// NEW in this commit: added payment processor credentials and a GitHub PAT
// These high-entropy strings test TitanShield's entropy scanner.
// ═══════════════════════════════════════════════════════════════════════════

// ── Hardcoded AWS credentials ─────────────────────────────────────────────
const AWS_ACCESS_KEY = "AKIA_TEST_TITANSHIELD_DEMO_KEY_XYZ";
const AWS_SECRET = "test/TITANSHIELD+DemoSecretKey+ForScan+Lab0001=";

// ── Hardcoded Stripe-style secret key ─────────────────────────────────────
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

// ── NEW: GitHub Personal Access Token (classic) ──────────────────────────
// High-entropy PAT pattern — entropy scanner + pattern match will catch this
const GITHUB_PAT = "ghp_TitanShieldTestTokenForHIBPScanningABC12345678";

// ── NEW: Twilio Auth Token ────────────────────────────────────────────────
// High entropy + RNG pattern typically indicates auth tokens
const TWILIO_AUTH_TOKEN = "TitanShield_a1b2c3d4e5f6789012345678901234ab";

// ── NEW: SendGrid API key ─────────────────────────────────────────────────
const SENDGRID_KEY = "SG.TitanShield_TestKey_ForScanLab_abcdef1234567890";

// ── NEW: Payment processor (Braintree) credentials ────────────────────────
const PAYMENT_CONFIG = {
    merchantId: "titanshield_test_merchant",
    publicKey: "TitanShield_pub_testkey89",
    privateKey: "TitanShieldPriv_TestKey_For_HIBP_Scan_qwerty12345",  // CWE-798
};

module.exports = {
    AWS_ACCESS_KEY, AWS_SECRET, STRIPE_KEY, JWT_SECRET, DB_CONFIG,
    GITHUB_PAT, TWILIO_AUTH_TOKEN, SENDGRID_KEY, PAYMENT_CONFIG
};
