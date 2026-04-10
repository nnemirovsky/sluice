-- Enforce uniqueness on (credential, destination) pairs so that the CLI and
-- REST API cannot create duplicate bindings through racing writers.
--
-- Upgrading an existing database can legitimately have multiple bindings for
-- the same (credential, destination) that differ on ports/protocols/header/
-- template/env_var. The resolver uses those extra columns to pick between
-- them, so silently collapsing them would drop information that the runtime
-- depends on. Instead of dropping rows, this migration fails loudly when a
-- true conflict exists so the operator can resolve it manually before
-- upgrading.
--
-- A "conflict" is a group of two or more bindings that share
-- (credential, destination) but differ on any of the behavioral columns
-- (ports, protocols, header, template, env_var). Rows that are exact
-- duplicates on all those columns (only the id differs) are safe to
-- collapse - that can happen when a pre-unique-index writer retried an
-- identical AddBinding call.
--
-- Implementation uses a temporary trigger to raise an ABORT with an
-- operator-facing error message. SQLite's RAISE() is only valid inside
-- triggers, so we create a temp table + temp trigger, run an INSERT whose
-- row count equals the number of conflict groups, and let the trigger fire
-- when that count is greater than zero. When there are no conflicts the
-- INSERT runs with a zero marker, the trigger does not fire, and the
-- migration proceeds to dedup exact duplicates and create the index.
CREATE TEMP TABLE _sluice_binding_conflict_check (
    conflict_count INTEGER
);

CREATE TEMP TRIGGER _sluice_binding_conflict_check_raise
  BEFORE INSERT ON _sluice_binding_conflict_check
  WHEN NEW.conflict_count > 0
BEGIN
    SELECT RAISE(
        ABORT,
        'sluice: upgrade blocked by conflicting bindings. Two or more bindings share the same (credential, destination) but differ on ports/protocols/header/template/env_var. Run "sluice binding list" on the old binary, merge or remove the conflicting rows, and then retry the upgrade.'
    );
END;

INSERT INTO _sluice_binding_conflict_check (conflict_count)
SELECT COUNT(*) FROM (
    SELECT 1
      FROM bindings b1
      JOIN bindings b2
        ON b1.credential = b2.credential
       AND b1.destination = b2.destination
       AND b1.id < b2.id
     WHERE COALESCE(b1.ports, '') != COALESCE(b2.ports, '')
        OR COALESCE(b1.header, '') != COALESCE(b2.header, '')
        OR COALESCE(b1.template, '') != COALESCE(b2.template, '')
        OR COALESCE(b1.protocols, '') != COALESCE(b2.protocols, '')
        OR COALESCE(b1.env_var, '') != COALESCE(b2.env_var, '')
);

DROP TRIGGER _sluice_binding_conflict_check_raise;
DROP TABLE _sluice_binding_conflict_check;

-- Safe to reach here: every remaining (credential, destination) group is
-- either a singleton or a set of byte-identical duplicates. Collapse the
-- identical duplicates to the lowest-id row so the UNIQUE index below can
-- be created without losing information.
--
-- Paired auto-created allow rules (tagged "binding-add:<cred>" or
-- "cred-add:<cred>") from the dropped identical bindings are also cleaned
-- up. AddRuleAndBinding inserts the rule and the binding together in one
-- transaction, so two retried writers each inserted their own paired rule.
-- We deduplicate those paired rules the same way: keep the lowest-id row
-- per (source, destination) and drop the rest. This is safe because:
--
--   1. One surviving binding still owns one rule, so enforcement stays
--      intact.
--   2. Rules kept after a deliberate "binding remove" are not touched:
--      they belong to a (source, destination) group with exactly one
--      row, so the MIN(id) predicate is an identity and nothing is
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
        GROUP BY source, destination
   );

DELETE FROM bindings
 WHERE id NOT IN (
     SELECT MIN(id) FROM bindings GROUP BY credential, destination
 );

CREATE UNIQUE INDEX IF NOT EXISTS idx_bindings_credential_destination
    ON bindings(credential, destination);
