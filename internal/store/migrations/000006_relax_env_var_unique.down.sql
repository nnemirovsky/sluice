-- Restore the full env_var uniqueness index. This down migration will
-- fail if the database currently contains two bindings (of any credential)
-- sharing the same env_var, which is the expected behavior: the operator
-- must manually reconcile before downgrading.
CREATE UNIQUE INDEX IF NOT EXISTS idx_bindings_env_var
    ON bindings(env_var) WHERE env_var IS NOT NULL AND env_var != '';
