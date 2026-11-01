-- Preserve v1 ciphertext and labels. Legacy records need explicit re-enrollment/grant.
ALTER TABLE credentials ADD COLUMN service_id TEXT NOT NULL DEFAULT 'synthetic-mock';
ALTER TABLE credentials ADD COLUMN credential_type TEXT NOT NULL DEFAULT 'api_key';
ALTER TABLE credentials ADD COLUMN account_alias TEXT NOT NULL DEFAULT '';
ALTER TABLE credentials ADD COLUMN version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1);
UPDATE credentials SET account_alias = 'legacy:' || id;
CREATE UNIQUE INDEX credential_identity ON credentials(owner_id, service_id, credential_type, account_alias);
CREATE TABLE operation_grants (
  record_id TEXT NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
  operation_id TEXT NOT NULL CHECK (operation_id = 'mock.account_summary'),
  PRIMARY KEY (record_id, operation_id)
);
CREATE TABLE enrollments (
  request_id TEXT PRIMARY KEY,
  owner TEXT NOT NULL CHECK (owner = 'local'),
  service_id TEXT NOT NULL CHECK (service_id = 'synthetic-mock'),
  credential_type TEXT NOT NULL CHECK (credential_type = 'api_key'),
  account_alias TEXT NOT NULL CHECK (length(account_alias) BETWEEN 1 AND 80),
  mode TEXT NOT NULL CHECK (mode IN ('create', 'replace')),
  target_record_id TEXT,
  expected_version INTEGER,
  status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'completed', 'conflict', 'expired', 'cancelled', 'locked')),
  operation_id TEXT CHECK (operation_id = 'mock.account_summary'),
  record_id TEXT,
  version INTEGER,
  expires_at INTEGER NOT NULL,
  CHECK ((mode = 'create' AND target_record_id IS NULL AND expected_version IS NULL) OR
         (mode = 'replace' AND target_record_id IS NOT NULL AND expected_version >= 1))
);
CREATE TABLE audit_events (
  request_id TEXT,
  record_id TEXT,
  owner TEXT NOT NULL CHECK (owner = 'local'),
  service TEXT NOT NULL CHECK (service = 'synthetic-mock'),
  action TEXT NOT NULL,
  version INTEGER,
  status TEXT NOT NULL,
  time INTEGER NOT NULL
);
PRAGMA user_version = 2;
