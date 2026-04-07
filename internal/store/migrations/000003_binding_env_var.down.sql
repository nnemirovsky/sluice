DROP INDEX IF EXISTS idx_bindings_env_var;

-- SQLite does not support DROP COLUMN in older versions.
-- Recreate the table without the env_var column.
CREATE TABLE bindings_backup (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    destination TEXT NOT NULL,
    ports TEXT,
    credential TEXT NOT NULL,
    header TEXT,
    template TEXT,
    protocols TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

INSERT INTO bindings_backup (id, destination, ports, credential, header, template, protocols, created_at)
    SELECT id, destination, ports, credential, header, template, protocols, created_at FROM bindings;

DROP TABLE bindings;

ALTER TABLE bindings_backup RENAME TO bindings;
