-- CSIRT Italia (ACN) bulletins that mention Microsoft
CREATE TABLE IF NOT EXISTS acn_items (
  id         TEXT PRIMARY KEY,           -- item link
  title      TEXT NOT NULL,
  link       TEXT NOT NULL,
  published  TEXT,
  summary    TEXT,
  keyword    TEXT,
  cves       TEXT,                       -- JSON array
  first_seen INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS acn_items_seen ON acn_items(first_seen);

-- Public alerts through the Telegram Watch bot
CREATE TABLE IF NOT EXISTS watch_subs (
  chat_id    TEXT NOT NULL,
  topic      TEXT NOT NULL,              -- all | patchtuesday | exploited | kev | oob | reinstall | acn | cve:<id> | kb:<id>
  created_at INTEGER NOT NULL,
  PRIMARY KEY (chat_id, topic)
);
CREATE INDEX IF NOT EXISTS watch_subs_topic ON watch_subs(topic);

CREATE TABLE IF NOT EXISTS watch_events (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  ts      INTEGER NOT NULL,
  topics  TEXT NOT NULL,                 -- comma separated
  title   TEXT NOT NULL,
  text    TEXT,
  link    TEXT,
  ref     TEXT UNIQUE                    -- source event id, prevents duplicates
);

CREATE TABLE IF NOT EXISTS watch_outbox (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id   INTEGER NOT NULL,
  chat_id    TEXT NOT NULL,
  attempts   INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  UNIQUE (event_id, chat_id)
);
