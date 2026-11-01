-- Client credentials share the Vault AEAD boundary; only provider and version are plaintext.
CREATE TABLE oauth_clients (
 owner_id TEXT NOT NULL CHECK(owner_id='local'),
 provider TEXT NOT NULL CHECK(provider IN ('github','google')),
 version INTEGER NOT NULL CHECK(version>0),
 encrypted TEXT NOT NULL,
 PRIMARY KEY(owner_id,provider)
);
PRAGMA user_version=4;
