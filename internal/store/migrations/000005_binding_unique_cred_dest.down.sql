-- Reverse the consolidated binding uniqueness migration. Drops the
-- (credential, LOWER(destination)) unique index and re-creates the
-- env_var unique index that migration 000003 originally installed so the
-- schema matches the version-4 state.
--
-- This down migration does not re-collapse rows. If the database contains
-- bindings whose env_var values now collide across credentials (legal
-- after the consolidated 000005, illegal under the version-3 index), the
-- operator must reconcile them manually before downgrading.
DROP INDEX IF EXISTS idx_bindings_credential_destination;

CREATE UNIQUE INDEX IF NOT EXISTS idx_bindings_env_var
    ON bindings(env_var) WHERE env_var IS NOT NULL AND env_var != '';
