-- MPatchMonitor security database (Cloudflare D1)

CREATE TABLE IF NOT EXISTS bans (
  ip            TEXT PRIMARY KEY,          -- IPv4 address or IPv6 /64 prefix
  reason        TEXT NOT NULL,
  source        TEXT NOT NULL DEFAULT 'auto',   -- auto | manual
  created_at    INTEGER NOT NULL,          -- epoch ms
  expires_at    INTEGER NOT NULL,          -- epoch ms
  offense_count INTEGER NOT NULL DEFAULT 1,
  country       TEXT,
  asn           TEXT,
  last_path     TEXT,
  user_agent    TEXT
);
CREATE INDEX IF NOT EXISTS bans_expires ON bans(expires_at);

CREATE TABLE IF NOT EXISTS ban_history (    -- remembers repeat offenders after a ban expires
  ip         TEXT PRIMARY KEY,
  offenses   INTEGER NOT NULL,
  last_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS allowlist (
  ip         TEXT PRIMARY KEY,
  note       TEXT,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  ts         INTEGER NOT NULL,
  ip         TEXT NOT NULL,
  kind       TEXT NOT NULL,                -- honeypot | attack | scanner | ratelimit | method | oversize | ban | unban | admin
  detail     TEXT,
  method     TEXT,
  path       TEXT,
  user_agent TEXT,
  country    TEXT,
  asn        TEXT,
  action     TEXT                          -- logged | blocked | banned
);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS events_ip ON events(ip);

CREATE TABLE IF NOT EXISTS alerts (         -- Telegram throttling
  key     TEXT PRIMARY KEY,
  last_at INTEGER NOT NULL
);

-- Admin authentication (passkeys)
CREATE TABLE IF NOT EXISTS credentials (
  id          TEXT PRIMARY KEY,            -- base64url credential id
  public_key  TEXT NOT NULL,               -- JWK (JSON)
  alg         INTEGER NOT NULL,            -- -7 ES256 | -257 RS256
  sign_count  INTEGER NOT NULL DEFAULT 0,
  name        TEXT,
  created_at  INTEGER NOT NULL,
  last_used   INTEGER
);

CREATE TABLE IF NOT EXISTS challenges (
  id         TEXT PRIMARY KEY,
  challenge  TEXT NOT NULL,
  kind       TEXT NOT NULL,                -- register | login
  expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  id         TEXT PRIMARY KEY,             -- SHA-256 of the session token
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  ip         TEXT,
  user_agent TEXT
);

-- Small mutable state (MSRC watcher status). Kept in D1 instead of KV because the cron
-- writes every 5 minutes and KV's free write quota (1,000/day) is shared by the whole account.
CREATE TABLE IF NOT EXISTS state (
  key        TEXT PRIMARY KEY,
  value      TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);
