ALTER TABLE entries ADD COLUMN wall TEXT;
CREATE INDEX IF NOT EXISTS idx_entries_wall ON entries (wall, created_at DESC);

CREATE TABLE IF NOT EXISTS walls (
  handle TEXT PRIMARY KEY,
  display_name TEXT NOT NULL,
  profile_json TEXT NOT NULL DEFAULT '{}',
  top8 TEXT NOT NULL DEFAULT '[]',
  created_at INTEGER NOT NULL
);

INSERT OR IGNORE INTO walls (handle, display_name, profile_json, top8, created_at)
VALUES (
  'adastroworld',
  'adastroworld',
  '{"mood":"nostalgic (◕‿◕✿)","currently":"vibecoding in minneapolis","interests":"glitter text, guestbooks, AI stuff","heroes":"Tom (ur first friend)","about":"welcome 2 my wall!!1 sign below xoxo (ﾉ◕ヮ◕)ﾉ*:･ﾟ✧"}',
  '[]',
  strftime('%s','now')
);
