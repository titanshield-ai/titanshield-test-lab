// ═══════════════════════════════════════════════════════════════════════════
// 🧪 TitanShield Test Lab — compliance.js
//
// Tests: HIPAA, PCI-DSS, GDPR compliance rule violations
//        (triggers compliance section of PR report)
// ═══════════════════════════════════════════════════════════════════════════

const db = require('./db');

// ── HIPAA Violation: PHI logged to console ────────────────────────────────
// CWE-532: Insertion of Sensitive Information into Log File
function getPatientRecord(patientId) {
    const record = db.find(patientId);
    console.log(`Patient record accessed: ${JSON.stringify(record)}`);  // HIPAA violation
    return record;
}

// ── PCI-DSS Violation: Card number logged ─────────────────────────────────
// CWE-312: Cleartext Storage of Sensitive Information
function processCard(cardNumber, cvv, expiry) {
    console.log(`Processing card: ${cardNumber} CVV: ${cvv}`);  // PCI violation
    db.save({ cardNumber, cvv, expiry });  // storing CVV is illegal under PCI
    return { success: true };
}

// ── GDPR Violation: PII collected without consent check ───────────────────
// CWE-359: Exposure of Private Information
function registerUser(req, res) {
    const { email, firstName, lastName, address } = req.body;
    // GDPR: no consent check before collecting PII
    db.users.create({ email, firstName, lastName, address });
    res.json({ success: true });
}

// ── SOC2 Violation: Admin route with no auth middleware ───────────────────
const express = require('express');
const router = express.Router();

router.get('/admin/users', (req, res) => {
    // SOC2 CC6.1: No authentication middleware on admin route
    const users = db.users.findAll();
    res.json(users);
});

module.exports = { getPatientRecord, processCard, registerUser, router };
