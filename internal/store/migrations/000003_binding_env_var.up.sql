ALTER TABLE bindings ADD COLUMN env_var TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_bindings_env_var
    ON bindings(env_var) WHERE env_var IS NOT NULL AND env_var != '';
