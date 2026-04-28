# 🛡️ Login Security Guard API

A Node.js API that simulates a login system protected by rate limiting, brute-force detection, and suspicious activity monitoring.

## 🚀 Quick Start

```bash
npm install
npm start
```

Open http://localhost:3000 to see the dashboard.

## 📡 API Endpoints

| Method | Route | Description |
|--------|-------|-------------|
| POST | `/login` | Authenticate a user |
| GET | `/security/events` | View recent security events |
| GET | `/security/suspicious` | View flagged suspicious IPs |
| GET | `/health` | Server health check |

## 🔐 POST /login

**Request:**
```json
{
  "username": "alice",
  "password": "password123"
}
```

**Success (200):**
```json
{
  "message": "Login successful",
  "user": { "username": "alice", "role": "admin" }
}
```

**Rate Limited (429):**
```json
{
  "error": "Too many attempts. Try again later.",
  "retryAfter": "10 minutes"
}
```

**Suspicious Activity (401):**
```json
{
  "error": "Login failed.",
  "warning": "Suspicious activity detected",
  "flags": ["EXCESSIVE_FAILURES", "RAPID_FIRE_ATTEMPTS"]
}
```

## 🔑 Test Credentials

| Username | Password | Role |
|----------|----------|------|
| alice | password123 | admin |
| bob | securepass | user |
| charlie | charlie99 | user |

## 🛡️ Security Features

- **Rate Limiting** — 10 login attempts per 10 minutes per IP (via `express-rate-limit`)
- **Brute Force Detection** — Tracks failed attempts in a sliding 10-minute window
- **Credential Stuffing Detection** — Flags IPs trying 3+ different usernames
- **Rapid Fire Detection** — Flags 3+ attempts within 30 seconds
- **Security Event Logging** — All events written to `logs/security.log`
- **Dashboard** — Live UI at `http://localhost:3000`

## 🧩 Project Structure

```
login-security-guard/
├── index.js              # Main server (Person A)
├── src/
│   ├── users.js          # Mock user DB + auth (Person A)
│   ├── rateLimiter.js    # Rate limiting middleware (Person B)
│   ├── tracker.js        # Attempt tracking + detection (Person C)
│   └── logger.js         # Logging system (Person D)
├── public/
│   └── index.html        # Security dashboard
└── logs/
    └── security.log      # Auto-generated log file
```
