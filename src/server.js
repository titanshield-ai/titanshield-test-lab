// ═══════════════════════════════════════════════════════════════════════════
// 🧪 TitanShield Test Lab — server.js
//
// Main entrypoint. Wires all the vulnerable modules together.
// This is the "clean" file — PRs modify the src/ files to trigger scans.
// ═══════════════════════════════════════════════════════════════════════════

const express = require('express');
const apiRouter = require('./api');
const { router: complianceRouter } = require('./compliance');

const app = express();
app.use(express.json());

// Mount vulnerable routers
app.use('/api', apiRouter);
app.use('/admin', complianceRouter);

// Health check (safe)
app.get('/health', (req, res) => {
    res.json({ status: 'ok', message: 'TitanShield Test Lab running' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🧪 TitanShield Test Lab listening on port ${PORT}`);
});
