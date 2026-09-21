CREATE TABLE IF NOT EXISTS entries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  message TEXT NOT NULL,
  website TEXT,
  created_at INTEGER NOT NULL,
  ip_hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_entries_created ON entries (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_entries_ip ON entries (ip_hash, created_at);
