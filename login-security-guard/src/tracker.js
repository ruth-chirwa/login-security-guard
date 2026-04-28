// Login attempt tracker - tracks failed attempts per IP
const attemptStore = new Map(); // IP -> { count, timestamps, usernames }

const CONFIG = {
  SUSPICIOUS_THRESHOLD: 5,      // failed attempts before suspicious flag
  WINDOW_MS: 10 * 60 * 1000,   // 10-minute sliding window
  BLOCK_AFTER: 10,              // hard block after this many failures
};

function getAttempts(ip) {
  const now = Date.now();
  if (!attemptStore.has(ip)) return { count: 0, timestamps: [], usernames: [] };

  // Prune old attempts outside the window
  const record = attemptStore.get(ip);
  record.timestamps = record.timestamps.filter(t => now - t < CONFIG.WINDOW_MS);
  record.count = record.timestamps.length;
  return record;
}

function recordFailedAttempt(ip, username) {
  const now = Date.now();
  const record = getAttempts(ip);
  record.timestamps.push(now);
  record.count = record.timestamps.length;
  if (!record.usernames) record.usernames = [];
  if (!record.usernames.includes(username)) record.usernames.push(username);
  attemptStore.set(ip, record);
  return record;
}

function resetAttempts(ip) {
  attemptStore.delete(ip);
}

function analyzeAttempts(ip, username) {
  const record = getAttempts(ip);
  const flags = [];

  // Too many failed attempts
  if (record.count >= CONFIG.BLOCK_AFTER) {
    return { blocked: true, suspicious: true, flags: ["BRUTE_FORCE_BLOCKED"] };
  }

  if (record.count >= CONFIG.SUSPICIOUS_THRESHOLD) {
    flags.push("EXCESSIVE_FAILURES");
  }

  // Multiple usernames tried from same IP (credential stuffing)
  if (record.usernames && record.usernames.length >= 3) {
    flags.push("CREDENTIAL_STUFFING");
  }

  // Rapid-fire attempts (more than 3 in 30 seconds)
  const recentWindow = 30 * 1000;
  const recentAttempts = record.timestamps.filter(t => Date.now() - t < recentWindow);
  if (recentAttempts.length >= 3) {
    flags.push("RAPID_FIRE_ATTEMPTS");
  }

  return {
    blocked: false,
    suspicious: flags.length > 0,
    flags,
    attemptCount: record.count,
  };
}

function getAllSuspiciousIPs() {
  const result = [];
  for (const [ip, record] of attemptStore.entries()) {
    if (record.count >= CONFIG.SUSPICIOUS_THRESHOLD) {
      result.push({ ip, ...record });
    }
  }
  return result;
}

module.exports = {
  recordFailedAttempt,
  resetAttempts,
  analyzeAttempts,
  getAllSuspiciousIPs,
  CONFIG,
};
