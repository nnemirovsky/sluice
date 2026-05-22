-- Per-pool agent auth-reset target.
--
-- auth_reset_target is an opt-in, per-pool string naming the agent auth
-- target sluice resets when the pool transitions exhausted -> recovered (e.g.
-- the hermes "openai-codex" auth entry). Empty (the default) = opt-out: no
-- reset runs. Non-empty = sluice invokes the agent profile's auth-reset
-- command on the recovery edge so a latched agent un-latches and resumes
-- without a manual operator reset.
--
-- A plain ADD COLUMN with a NOT NULL DEFAULT '' is sufficient for SQLite; the
-- down migration does the 12-step table rebuild because SQLite cannot DROP a
-- column referenced by no FK in older engines portably, and the column must be
-- removed while preserving the credential_pool_members FK -> credential_pools.

ALTER TABLE credential_pools ADD COLUMN auth_reset_target TEXT NOT NULL DEFAULT '';
