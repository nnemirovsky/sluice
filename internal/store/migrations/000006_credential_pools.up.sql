-- Credential pools with auto-failover.
--
-- A pool is a named group of OAuth credentials. A single phantom identity
-- the agent sees is backed by N real OAuth credentials; sluice picks which
-- real account to inject and fails over between members on 429/401.
--
--   credential_pools         one row per pool (strategy reserved: failover only)
--   credential_pool_members  ordered membership; position drives failover order
--   credential_health        per-credential health used to skip cooled-down
--                            members during active-member selection
--
-- A pool name and a credential name share one namespace; mutual exclusion
-- is enforced at the application layer (see store.CreatePoolWithMembers and
-- the cred-add path), not by a cross-table SQL constraint.

CREATE TABLE credential_pools (
    name TEXT PRIMARY KEY,
    strategy TEXT NOT NULL DEFAULT 'failover' CHECK(strategy IN ('failover')),
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE credential_pool_members (
    pool TEXT NOT NULL,
    credential TEXT NOT NULL,
    position INTEGER NOT NULL,
    PRIMARY KEY (pool, credential),
    FOREIGN KEY (pool) REFERENCES credential_pools(name) ON DELETE CASCADE
);

CREATE TABLE credential_health (
    credential TEXT PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'healthy' CHECK(status IN ('healthy','cooldown')),
    cooldown_until TEXT,
    last_failure_reason TEXT,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
