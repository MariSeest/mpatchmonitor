-- Language of each Watch bot chat, and Italian text for alerts
CREATE TABLE IF NOT EXISTS watch_chats (
  chat_id    TEXT PRIMARY KEY,
  lang       TEXT NOT NULL DEFAULT 'en',  -- en | it
  updated_at INTEGER NOT NULL
);

ALTER TABLE watch_events ADD COLUMN title_it TEXT;
ALTER TABLE watch_events ADD COLUMN text_it TEXT;
