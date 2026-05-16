-- Pool membership epoch.
--
-- A pool name + a credential name share one namespace and the
-- credential_health table is NOT foreign-keyed to live membership. A
-- credential removed from a pool (or whose pool was removed) and then
-- re-created/re-added under the SAME name produces a row with the SAME
-- (pool, credential) primary key. Without an epoch, a stale in-flight
-- failover write — the durable SetCredentialHealthIfPoolMember from a
-- detached goroutine, a manual `pool rotate`, or an old-generation
-- resolver's MarkCooldown — could not tell the OLD membership from its
-- re-created successor, so it would wrongly park the NEW member with the
-- OLD response's cooldown.
--
-- pool_membership_epoch is a single-row monotonic counter bumped on every
-- pool create and pool remove. Each credential_pool_members row is stamped
-- with the counter value live at insert time, so a remove/re-add cycle
-- yields a strictly greater epoch on the successor row. The guarded health
-- write and MarkCooldown gate on (credential, pool, epoch): a stale write
-- carrying the old epoch finds no matching row and no-ops, while a
-- genuinely-still-live member (same epoch) still persists/rotates
-- (CRITICAL-1 durability + round-9/11/14/15 fixes preserved).

CREATE TABLE pool_membership_epoch (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    epoch INTEGER NOT NULL DEFAULT 0
);

INSERT INTO pool_membership_epoch (id, epoch) VALUES (1, 0);

ALTER TABLE credential_pool_members ADD COLUMN epoch INTEGER NOT NULL DEFAULT 0;
