CREATE TABLE vault_meta (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  version INTEGER NOT NULL CHECK (version = 1),
  salt TEXT NOT NULL,
  verifier TEXT NOT NULL,
  execution_hash TEXT NOT NULL,
  unlock_failures INTEGER NOT NULL DEFAULT 0,
  unlock_blocked_until INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE credentials (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL CHECK (owner_id = 'local'),
  label TEXT NOT NULL,
  provider TEXT NOT NULL CHECK (provider = 'synthetic-mock'),
  encrypted TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
PRAGMA user_version = 1;
