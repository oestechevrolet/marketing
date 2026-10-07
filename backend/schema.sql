CREATE TABLE IF NOT EXISTS request_status (
  submission_id TEXT PRIMARY KEY,
  status TEXT NOT NULL DEFAULT 'pending',
  note TEXT,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
