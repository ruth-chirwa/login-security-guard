const fs = require("fs");
const path = require("path");

const LOG_FILE = path.join(__dirname, "../logs/security.log");

// Ensure logs directory exists
if (!fs.existsSync(path.dirname(LOG_FILE))) {
  fs.mkdirSync(path.dirname(LOG_FILE), { recursive: true });
}

// In-memory log for the dashboard
const recentEvents = [];
const MAX_RECENT = 100;

function log(level, event, details = {}) {
  const entry = {
    timestamp: new Date().toISOString(),
    level,
    event,
    ...details,
  };

  const line = JSON.stringify(entry);

  // Write to file
  fs.appendFileSync(LOG_FILE, line + "\n");

  // Keep in-memory for dashboard
  recentEvents.unshift(entry);
  if (recentEvents.length > MAX_RECENT) recentEvents.pop();

  // Console output with color codes
  const colors = { INFO: "\x1b[36m", WARN: "\x1b[33m", ALERT: "\x1b[31m", SUCCESS: "\x1b[32m" };
  const reset = "\x1b[0m";
  const color = colors[level] || "";
  console.log(`${color}[${level}] ${entry.timestamp} | ${event}${reset}`, details);
}

function getRecentEvents() {
  return recentEvents;
}

module.exports = { log, getRecentEvents };
