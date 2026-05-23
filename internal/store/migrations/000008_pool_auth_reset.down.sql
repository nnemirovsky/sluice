-- Revert the per-pool auth_reset_target column.
--
-- This is the SQLite 12-step table rebuild
-- (https://www.sqlite.org/lang_altertable.html#otheralter) for
-- credential_pools: recreate it WITHOUT auth_reset_target, copy the data, drop
-- the old table, rename. The column set + constraints recreated here match
-- credential_pools as created by migration 000006 (name PK, strategy CHECK,
-- created_at default).
--
-- credential_pool_members.pool has a FK -> credential_pools(name) with ON
-- DELETE CASCADE. golang-migrate runs each migration inside a transaction, and
-- SQLite ignores `PRAGMA foreign_keys=OFF` while a transaction is open, so the
-- pragma trick used outside migrations cannot disable the cascade here.
-- Dropping credential_pools would therefore CASCADE-delete every member row.
--
-- To keep the FK-referencing member rows (and their epoch column from 000007)
-- intact across the rebuild, the member rows are snapshotted into a temp table
-- before the parent table is dropped and restored afterward, once the rebuilt
-- credential_pools rows exist again to satisfy the FK. credential_health is
-- not FK-tied to credential_pools, so it is untouched.

CREATE TEMP TABLE _cpm_backup AS
    SELECT pool, credential, position, epoch FROM credential_pool_members;

CREATE TABLE credential_pools_new (
    name TEXT PRIMARY KEY,
    strategy TEXT NOT NULL DEFAULT 'failover' CHECK(strategy IN ('failover')),
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

INSERT INTO credential_pools_new (name, strategy, created_at)
    SELECT name, strategy, created_at FROM credential_pools;

DROP TABLE credential_pools;

ALTER TABLE credential_pools_new RENAME TO credential_pools;

INSERT INTO credential_pool_members (pool, credential, position, epoch)
    SELECT pool, credential, position, epoch FROM _cpm_backup;

DROP TABLE _cpm_backup;
