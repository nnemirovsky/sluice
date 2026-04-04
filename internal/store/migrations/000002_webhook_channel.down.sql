-- SQLite does not support DROP COLUMN before 3.35.0. Rebuild the table
-- without webhook_url and webhook_secret columns.
CREATE TABLE channels_backup (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

INSERT INTO channels_backup (id, type, enabled, created_at)
    SELECT id, type, enabled, created_at FROM channels;

DROP TABLE channels;

ALTER TABLE channels_backup RENAME TO channels;
