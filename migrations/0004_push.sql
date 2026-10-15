-- Browser notifications (Web Push). Only the browser's push address, its encryption keys,
-- the chosen topics and the language are stored. Unsubscribing deletes everything.
CREATE TABLE IF NOT EXISTS push_subs (
  id         TEXT PRIMARY KEY,           -- hash of the endpoint
  endpoint   TEXT NOT NULL,
  p256dh     TEXT NOT NULL,
  auth       TEXT NOT NULL,
  lang       TEXT NOT NULL DEFAULT 'en',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS push_topics (
  sub_id TEXT NOT NULL,
  topic  TEXT NOT NULL,
  PRIMARY KEY (sub_id, topic)
);
CREATE INDEX IF NOT EXISTS push_topics_topic ON push_topics(topic);

CREATE TABLE IF NOT EXISTS push_outbox (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id   INTEGER NOT NULL,
  sub_id     TEXT NOT NULL,
  attempts   INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  UNIQUE (event_id, sub_id)
);
