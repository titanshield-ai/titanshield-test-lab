// ═══════════════════════════════════════════════════════════════════════════
// 🧪 TitanShield Test Lab — api.js
//
// Tests: Feature 1 (Blast Radius), Feature 2 (Attack Simulation PoC)
//
// Intentional vulnerabilities:
//   CWE-89:  SQL Injection (no parameterized queries)
//   CWE-78:  Command Injection (unsanitized exec)
//   CWE-79:  XSS (unescaped user input rendered)
//   CWE-918: SSRF (user-controlled URL fetch)
// ═══════════════════════════════════════════════════════════════════════════

const express = require('express');
const mysql = require('mysql');
const { exec } = require('child_process');
const axios = require('axios');

const router = express.Router();
const db = mysql.createConnection({ host: 'localhost', user: 'root', database: 'app' });

// ── CWE-89: SQL Injection ─────────────────────────────────────────────────
// VULNERABLE: user input injected directly into SQL query string
router.get('/users/:id', (req, res) => {
    const query = `SELECT * FROM users WHERE id = ${req.params.id}`;
    db.query(query, (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});

// ── CWE-89: SQL Injection (login) ─────────────────────────────────────────
router.post('/login', (req, res) => {
    const { username, password } = req.body;
    const sql = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;
    db.query(sql, (err, results) => {
        if (results.length > 0) {
            res.json({ success: true, user: results[0] });
        } else {
            res.status(401).json({ success: false });
        }
    });
});

// ── CWE-78: OS Command Injection ──────────────────────────────────────────
// VULNERABLE: req.body.filename passed directly to shell
router.post('/download', (req, res) => {
    const filename = req.body.filename;
    exec(`cat /var/data/${filename}`, (error, stdout) => {
        res.send(stdout);
    });
});

// ── CWE-79: Cross-Site Scripting (XSS) ───────────────────────────────────
// VULNERABLE: username rendered without escaping
router.get('/profile', (req, res) => {
    const username = req.query.username;
    res.send(`<html><body><h1>Welcome, ${username}!</h1></body></html>`);
});

// ── CWE-918: Server-Side Request Forgery (SSRF) ───────────────────────────
// VULNERABLE: user controls the URL being fetched server-side
router.post('/proxy', async (req, res) => {
    const targetUrl = req.body.url;
    const response = await axios.get(targetUrl);
    res.json(response.data);
});

module.exports = router;

// ── TRIGGER: Additional finding to ensure scan fires ─────────────────────
// CWE-502: Deserialization of Untrusted Data
const payload = JSON.parse(req.body.data);
eval(payload.code);  // CWE-78 + CWE-95: Code Injection via eval
