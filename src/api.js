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
// Define a safe set of allowed operations at the top of your file or in a separate module
const allowedOperations = {
  add: (a, b) => {
    if (typeof a !== 'number' || typeof b !== 'number') throw new TypeError('Invalid arguments for add');
    return a + b;
  },
  subtract: (a, b) => {
    if (typeof a !== 'number' || typeof b !== 'number') throw new TypeError('Invalid arguments for subtract');
    return a - b;
  },
  // Add other safe, predefined functions here
};

// Replace the existing route handler logic with this:
let payload;
try {
  if (typeof req.body.data !== 'string') {
      return res.status(400).json({ error: 'Invalid payload format. "data" field must be a JSON string.' });
  }
  payload = JSON.parse(req.body.data);
} catch (e) {
  return res.status(400).json({ error: 'Invalid JSON in "data" field.' });
}

const { operation, args } = payload;
if (typeof operation !== 'string' || !allowedOperations.hasOwnProperty(operation)) {
  console.warn(`Security event: Invalid operation attempted: "${operation}"`);
  return res.status(400).json({ error: 'Invalid or unsupported operation.' });
}

if (!Array.isArray(args)) {
  return res.status(400).json({ error: 'Arguments must be provided as an array.' });
}

try {
  const func = allowedOperations[operation];
  const result = func(...args);
  res.status(200).json({ success: true, result });
} catch (error) {
  console.error(`Error executing operation '${operation}':`, error.message);
  res.status(500).json({ error: 'An error occurred during operation execution.' });
}  // CWE-78 + CWE-95: Code Injection via eval
