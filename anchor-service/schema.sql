-- CORD anchor service — D1 schema.
-- Apply: wrangler d1 execute cord-anchors --file=schema.sql

CREATE TABLE IF NOT EXISTS clients (
  client_id  TEXT PRIMARY KEY,
  public_key TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS anchors (
  log_id           TEXT    NOT NULL,
  seq              INTEGER NOT NULL,
  client_id        TEXT    NOT NULL,
  entry_count      INTEGER,
  chain_head       TEXT,
  prev_anchor_head TEXT,
  ts_client        TEXT,
  ts_server        TEXT,
  server_sig       TEXT,
  sig              TEXT,
  -- (log_id, seq) unique: a duplicate seq is a hard DB error, so replay
  -- can't slip through even if the logic check were bypassed.
  PRIMARY KEY (log_id, seq)
);

CREATE TABLE IF NOT EXISTS quarantine (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  log_id  TEXT,
  payload TEXT,
  at      TEXT
);
