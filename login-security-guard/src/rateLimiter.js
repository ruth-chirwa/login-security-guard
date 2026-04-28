const rateLimit = require("express-rate-limit");
const { log } = require("./logger");

// Global rate limiter: 100 requests per 15 minutes per IP
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    const ip = req.ip || req.connection.remoteAddress;
    log("ALERT", "GLOBAL_RATE_LIMIT_HIT", { ip, path: req.path });
    res.status(429).json({ error: "Too many requests. Please slow down." });
  },
});

// Strict login limiter: 10 attempts per 10 minutes per IP
const loginLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    const ip = req.ip || req.connection.remoteAddress;
    log("ALERT", "LOGIN_RATE_LIMIT_BLOCKED", { ip, username: req.body?.username });
    res.status(429).json({
      error: "Too many attempts. Try again later.",
      retryAfter: "10 minutes",
    });
  },
});

module.exports = { globalLimiter, loginLimiter };
