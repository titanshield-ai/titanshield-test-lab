# TitanShield Security Test Lab 🧪

This repository is intentionally full of security vulnerabilities to demonstrate and validate all **7 world-first PR security features** built into [TitanShield](https://titanshield.ai).

> ⚠️ **DO NOT deploy this code anywhere.** Every file in `src/` contains intentional, real security vulnerabilities for testing purposes only.

---

## What This Repo Tests

| Feature | Test File | How to Trigger |
|---|---|---|
| 🧬 Blast Radius | `src/auth.js` | Open any PR changing auth functions |
| ⚡ Attack Simulation PoC | `src/api.js` | SQL injection, command injection |
| 🤝 AI Negotiation Bot | Any PR | Comment `@titanshield-security-ai why is this a Critical?` |
| 🧠 Trend Report | After 2+ PRs | Automatically appears in comment |
| 🔐 HIBP Secret Check | `src/config.js` | Hardcoded credentials |
| 📋 SBOM on Merge | `package.json` | Merge any PR |
| 📊 Security Gating | Any vuln PR | Check shows FAILED, merge blocked |

## How to Run a Validation Test

```bash
# 1. Create a test branch
git checkout -b test/feature-validation-$(date +%s)

# 2. Make a small change to any src/ file
echo "// trigger scan $(date)" >> src/api.js

# 3. Push and open a PR
git add . && git commit -m "test: trigger TitanShield security scan"
git push origin HEAD

# 4. Open a PR on GitHub → TitanShield will scan automatically
```

After the scan completes (30-90 seconds), check the PR for:
- ❌ **SECURITY GATE FAILED** check (Feature 7)
- 🚀  Detailed PR comment with all findings (Features 1-6)
- 🤝 Post `@titanshield-security-ai why is CWE-89 a critical?` (Feature 3)
- 🔀 Merge the PR to get the SBOM comment (Feature 6)
