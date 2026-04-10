-- Revert to the case-sensitive unique index from 000005. Down migrations
-- do not re-collapse rows, so if the database contains entries that only
-- differ by destination case the operator must reconcile them manually
-- before downgrading.
DROP INDEX IF EXISTS idx_bindings_credential_destination;

CREATE UNIQUE INDEX IF NOT EXISTS idx_bindings_credential_destination
    ON bindings(credential, destination);
