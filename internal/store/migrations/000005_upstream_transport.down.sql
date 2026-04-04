-- SQLite does not support DROP COLUMN before 3.35.0, so we recreate the table.
CREATE TABLE mcp_upstreams_backup AS SELECT id, name, command, args, env, timeout_sec, created_at FROM mcp_upstreams;
DROP TABLE mcp_upstreams;
CREATE TABLE mcp_upstreams (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    command TEXT NOT NULL,
    args TEXT,
    env TEXT,
    timeout_sec INTEGER DEFAULT 120,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
INSERT INTO mcp_upstreams (id, name, command, args, env, timeout_sec, created_at) SELECT id, name, command, args, env, timeout_sec, created_at FROM mcp_upstreams_backup;
DROP TABLE mcp_upstreams_backup;
