const express = require("express");
const path = require("path");
const { globalLimiter, loginLimiter } = require("./src/rateLimiter");
const { validateUser } = require("./src/users");
const { recordFailedAttempt, resetAttempts, analyzeAttempts, getAllSuspiciousIPs } = require("./src/tracker");
const { log, getRecentEvents } = require("./src/logger");

const app = express();
const PORT = process.env.PORT || 3000;

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));
app.use(globalLimiter);

// ─── POST /login ──────────────────────────────────────────────────────────────
app.post("/login", loginLimiter, (req, res) => {
  const { username, password } = req.body;
  const ip = req.ip || req.connection.remoteAddress;

  // Input validation
  if (!username || !password) {
    log("WARN", "INVALID_REQUEST", { ip, reason: "missing_fields" });
    return res.status(400).json({ error: "Username and password are required." });
  }

  // Pre-check: analyze this IP's history BEFORE attempting login
  const preCheck = analyzeAttempts(ip, username);

  if (preCheck.blocked) {
    log("ALERT", "LOGIN_BLOCKED_BRUTE_FORCE", { ip, username, flags: preCheck.flags });
    return res.status(429).json({
      error: "Too many attempts. Try again later.",
      flags: preCheck.flags,
    });
  }

  // Attempt authentication
  const result = validateUser(username, password);

  if (!result.valid) {
    // Record the failed attempt
    recordFailedAttempt(ip, username);
    const analysis = analyzeAttempts(ip, username);

    log("WARN", "LOGIN_FAILED", {
      ip,
      username,
      reason: result.reason,
      attemptCount: analysis.attemptCount,
      flags: analysis.flags,
    });

    if (analysis.suspicious) {
      log("ALERT", "SUSPICIOUS_ACTIVITY_DETECTED", { ip, username, flags: analysis.flags });
      return res.status(401).json({
        error: "Login failed.",
        warning: "Suspicious activity detected",
        flags: analysis.flags,
      });
    }

    return res.status(401).json({
      error: "Invalid username or password.",
      attemptsRemaining: Math.max(0, 10 - analysis.attemptCount),
    });
  }

  // ✅ Successful login
  resetAttempts(ip); // Clear failed attempts on success
  log("SUCCESS", "LOGIN_SUCCESS", { ip, username, role: result.role });

  return res.status(200).json({
    message: "Login successful",
    user: { username, role: result.role },
  });
});

// ─── GET /security/events ─────────────────────────────────────────────────────
app.get("/security/events", (req, res) => {
  res.json({ events: getRecentEvents() });
});

// ─── GET /security/suspicious ─────────────────────────────────────────────────
app.get("/security/suspicious", (req, res) => {
  res.json({ suspiciousIPs: getAllSuspiciousIPs() });
});

// ─── GET /health ──────────────────────────────────────────────────────────────
app.get("/health", (req, res) => {
  res.json({ status: "ok", uptime: process.uptime(), timestamp: new Date().toISOString() });
});

// ─── Serve Dashboard ──────────────────────────────────────────────────────────
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ─── Start Server ─────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\x1b[32m✓ Login Security Guard API running on http://localhost:${PORT}\x1b[0m`);
  console.log(`\x1b[36m  Dashboard: http://localhost:${PORT}\x1b[0m`);
  console.log(`\x1b[36m  POST /login | GET /security/events | GET /security/suspicious\x1b[0m`);
});

module.exports = app;
