CREATE TABLE credential_meta (
    name TEXT PRIMARY KEY,
    cred_type TEXT NOT NULL DEFAULT 'static',
    token_url TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
