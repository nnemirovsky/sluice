-- Relax the env_var uniqueness constraint so multiple bindings belonging
-- to the same credential can share a single env_var. Different bindings of
-- the same credential resolve to the same phantom value (the phantom is
-- derived from the credential name), so container injection has no
-- conflict. Cross-credential uniqueness is still enforced at the Go level
-- by checkEnvVarUniqueWith, which is the only path that knows which
-- bindings belong to which credential.
DROP INDEX IF EXISTS idx_bindings_env_var;
