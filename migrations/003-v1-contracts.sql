-- Preserve every existing AEAD envelope and its original AAD. No decryption in migration.
ALTER TABLE vault_meta ADD COLUMN auth_salt TEXT;
ALTER TABLE vault_meta ADD COLUMN auth_verifier TEXT;
ALTER TABLE vault_meta ADD COLUMN security_epoch INTEGER NOT NULL DEFAULT 0;
CREATE TABLE connections (
 id TEXT PRIMARY KEY, owner_id TEXT NOT NULL CHECK(owner_id='local'), label TEXT NOT NULL,
 provider TEXT NOT NULL, service_id TEXT NOT NULL, credential_type TEXT NOT NULL,
 account_alias TEXT NOT NULL, origin TEXT NOT NULL, environment TEXT NOT NULL CHECK(environment='local'),
 encrypted TEXT NOT NULL, encryption_context TEXT NOT NULL,
 granted_operations TEXT NOT NULL, record_version INTEGER NOT NULL CHECK(record_version>0),
 status_version INTEGER NOT NULL CHECK(status_version>0), material_version INTEGER NOT NULL CHECK(material_version>0),
 status TEXT NOT NULL, last_verified_at TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 UNIQUE(owner_id,service_id,credential_type,account_alias)
);
INSERT INTO connections
 SELECT id,owner_id,label,provider,service_id,credential_type,account_alias,
 'http://127.0.0.1:43121','local',encrypted,
 'agent-vault:v1:local:'||id||':synthetic-mock:token','[]',version,1,1,'paused',NULL,created_at,updated_at FROM credentials;
DROP TABLE operation_grants;
DROP TABLE enrollments;
ALTER TABLE audit_events RENAME TO legacy_audit_events_v2;
DROP TABLE credentials;
ALTER TABLE connections RENAME TO credentials;
CREATE TABLE requests (
 owner_id TEXT NOT NULL, principal_id TEXT NOT NULL, operation_name TEXT NOT NULL, request_id TEXT NOT NULL,
 registered_at INTEGER NOT NULL, retain_until INTEGER NOT NULL, canonical_encrypted TEXT,
 result TEXT, state TEXT NOT NULL, connection_id TEXT, business_target TEXT, semantics TEXT,
 operation_status_version INTEGER NOT NULL DEFAULT 1, dispatch_epoch INTEGER,
 PRIMARY KEY(owner_id,principal_id,operation_name,request_id)
);
CREATE INDEX unknown_operation_conflict ON requests(connection_id,operation_name,business_target,state);
CREATE TABLE audit_events (
 id INTEGER PRIMARY KEY, owner_id TEXT NOT NULL, principal_id TEXT NOT NULL, action TEXT NOT NULL,
 record_id TEXT, record_version INTEGER, status_version INTEGER, time INTEGER NOT NULL
);
INSERT INTO audit_events(owner_id,principal_id,action,record_id,record_version,status_version,time)
 SELECT owner,'legacy:unmapped','legacy_event_preserved',record_id,version,NULL,time FROM legacy_audit_events_v2;
CREATE TABLE consumed_drafts (
 draft_id TEXT PRIMARY KEY, epoch INTEGER NOT NULL, request_id TEXT NOT NULL, consumed_at INTEGER NOT NULL
);
CREATE TABLE material_leases (
 connection_id TEXT PRIMARY KEY REFERENCES credentials(id) ON DELETE CASCADE,
 lease_id TEXT NOT NULL UNIQUE, epoch INTEGER NOT NULL, record_version INTEGER NOT NULL,
 status_version INTEGER NOT NULL, material_version INTEGER NOT NULL, action TEXT NOT NULL,
 principal_id TEXT NOT NULL, state TEXT NOT NULL, created_at INTEGER NOT NULL
);
PRAGMA user_version=3;
