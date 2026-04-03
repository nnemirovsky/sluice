CREATE TABLE rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    verdict TEXT NOT NULL CHECK(verdict IN ('allow', 'deny', 'ask', 'redact')),
    destination TEXT,
    tool TEXT,
    pattern TEXT,
    replacement TEXT,
    ports TEXT,
    protocols TEXT,
    name TEXT,
    source TEXT NOT NULL DEFAULT 'manual',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    CHECK(
        (destination IS NOT NULL AND tool IS NULL AND pattern IS NULL) OR
        (tool IS NOT NULL AND destination IS NULL AND pattern IS NULL) OR
        (pattern IS NOT NULL AND destination IS NULL AND tool IS NULL)
    )
);

CREATE TABLE config (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    default_verdict TEXT NOT NULL DEFAULT 'deny' CHECK(default_verdict IN ('allow', 'deny', 'ask')),
    timeout_sec INTEGER NOT NULL DEFAULT 120,
    vault_provider TEXT NOT NULL DEFAULT 'age',
    vault_dir TEXT,
    vault_providers TEXT,
    vault_hashicorp_addr TEXT,
    vault_hashicorp_mount TEXT DEFAULT 'secret',
    vault_hashicorp_prefix TEXT,
    vault_hashicorp_auth TEXT DEFAULT 'token',
    vault_hashicorp_token TEXT,
    vault_hashicorp_role_id TEXT,
    vault_hashicorp_secret_id TEXT,
    vault_hashicorp_role_id_env TEXT,
    vault_hashicorp_secret_id_env TEXT
);

INSERT OR IGNORE INTO config (id) VALUES (1);

CREATE TABLE bindings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    destination TEXT NOT NULL,
    ports TEXT,
    credential TEXT NOT NULL,
    header TEXT,
    template TEXT,
    protocols TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE mcp_upstreams (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    command TEXT NOT NULL,
    args TEXT,
    env TEXT,
    timeout_sec INTEGER DEFAULT 120,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE channels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

INSERT OR IGNORE INTO channels (id, type) VALUES (1, 0);
