-- Tighten binding uniqueness in one atomic schema change.
--
-- This migration does three things:
--
--   1. Drops idx_bindings_env_var. The unique-on-env_var index from
--      migration 000003 prevented multiple bindings of the same credential
--      from sharing one env_var, but different bindings of the same
--      credential resolve to the same phantom value (the phantom is derived
--      from the credential name) so container injection has no conflict.
--      Cross-credential uniqueness is still enforced at the Go level by
--      checkEnvVarUniqueWith, which is the only path that knows which
--      bindings belong to which credential.
--
--   2. Detects pre-existing bindings that share
--      (credential, LOWER(destination)) but differ on any of the behavioral
--      columns (ports/protocols/header/template/env_var) and aborts the
--      upgrade with an operator-facing message. The resolver picks between
--      bindings based on those columns at runtime, so silently collapsing
--      conflicting rows would drop information the runtime depends on.
--      Destination is compared case-insensitively because policy matching
--      (policy.CompileGlob) compiles destinations with a "(?i)" prefix.
--      "API.EXAMPLE.COM" and "api.example.com" therefore match the same
--      set of connections and must be treated as duplicates.
--
--   3. Collapses byte-identical case-insensitive duplicates to the
--      lowest-id row, then creates a UNIQUE index on
--      (credential, LOWER(destination)) so future writers cannot race past
--      the application-level check.
--
-- Implementation note for step 2: SQLite's RAISE() is only valid inside
-- triggers, so we create a temp table + temp trigger, run an INSERT whose
-- row count equals the number of conflict groups, and let the trigger
-- ABORT when that count is greater than zero. When there are no conflicts
-- the INSERT runs with a zero marker, the trigger does not fire, and the
-- migration proceeds to dedup and create the index.

DROP INDEX IF EXISTS idx_bindings_env_var;

CREATE TEMP TABLE _sluice_binding_conflict_check (
    conflict_count INTEGER
);

CREATE TEMP TRIGGER _sluice_binding_conflict_check_raise
  BEFORE INSERT ON _sluice_binding_conflict_check
  WHEN NEW.conflict_count > 0
BEGIN
    SELECT RAISE(
        ABORT,
        'sluice: upgrade blocked by conflicting bindings. Two or more bindings share the same (credential, LOWER(destination)) but differ on ports/protocols/header/template/env_var. Run "sluice binding list" on the old binary, merge or remove the conflicting rows, and then retry the upgrade.'
    );
END;

INSERT INTO _sluice_binding_conflict_check (conflict_count)
SELECT COUNT(*) FROM (
    SELECT 1
      FROM bindings b1
      JOIN bindings b2
        ON b1.credential = b2.credential
       AND LOWER(b1.destination) = LOWER(b2.destination)
       AND b1.id < b2.id
     WHERE COALESCE(b1.ports, '') != COALESCE(b2.ports, '')
        OR COALESCE(b1.header, '') != COALESCE(b2.header, '')
        OR COALESCE(b1.template, '') != COALESCE(b2.template, '')
        OR COALESCE(b1.protocols, '') != COALESCE(b2.protocols, '')
        OR COALESCE(b1.env_var, '') != COALESCE(b2.env_var, '')
);

DROP TRIGGER _sluice_binding_conflict_check_raise;
DROP TABLE _sluice_binding_conflict_check;

-- Safe to reach here: every remaining (credential, LOWER(destination))
-- group is either a singleton or a set of byte-identical duplicates.
-- Collapse the identical duplicates to the lowest-id row so the UNIQUE
-- index below can be created without losing information.
--
-- Paired auto-created allow rules (tagged "binding-add:<cred>" or
-- "cred-add:<cred>") from the dropped bindings are also cleaned up.
-- AddRuleAndBinding inserts the rule and the binding together in one
-- transaction, so two retried writers each inserted their own paired rule.
-- We deduplicate those paired rules the same way: keep the lowest-id row
-- per (source, LOWER(destination)) and drop the rest. This is safe
-- because:
--
--   1. One surviving binding still owns one rule, so enforcement stays
--      intact.
--   2. Rules kept after a deliberate "binding remove" are not touched:
--      they belong to a (source, LOWER(destination)) group with exactly
--      one row, so the MIN(id) predicate is an identity and nothing is
--      deleted.
--   3. Unrelated rules (source = 'manual' or other tags) are ignored
--      by the source LIKE filter.
DELETE FROM rules
 WHERE (source LIKE 'binding-add:%' OR source LIKE 'cred-add:%')
   AND destination IS NOT NULL
   AND id NOT IN (
       SELECT MIN(id) FROM rules
        WHERE (source LIKE 'binding-add:%' OR source LIKE 'cred-add:%')
          AND destination IS NOT NULL
        GROUP BY source, LOWER(destination)
   );

DELETE FROM bindings
 WHERE id NOT IN (
     SELECT MIN(id) FROM bindings GROUP BY credential, LOWER(destination)
 );

CREATE UNIQUE INDEX IF NOT EXISTS idx_bindings_credential_destination
    ON bindings(credential, LOWER(destination));
