-- Make the (credential, destination) uniqueness check case-insensitive on
-- destination. Policy matching (policy.CompileGlob) compiles destinations
-- with a "(?i)" prefix, so "API.EXAMPLE.COM" and "api.example.com" match
-- the same set of connections. Before this migration the UNIQUE index in
-- 000005 was case-sensitive, so two bindings differing only in destination
-- case could coexist and produce nondeterministic credential injection.
--
-- Like 000005, this migration refuses to drop operator data. Case-variant
-- duplicates that also differ on ports/protocols/header/template/env_var
-- carry information the resolver depends on, so we raise a loud error
-- asking the operator to resolve them on the old binary before upgrading.
-- Only exact-case and all-behavioral-columns duplicates (which already
-- compare equal to the case-sensitive index from 000005 in the exact-case
-- subset, or were somehow skipped because 000005 ran before this file was
-- introduced) are collapsed to the lowest-id row.
CREATE TEMP TABLE _sluice_binding_conflict_check_nocase (
    conflict_count INTEGER
);

CREATE TEMP TRIGGER _sluice_binding_conflict_check_nocase_raise
  BEFORE INSERT ON _sluice_binding_conflict_check_nocase
  WHEN NEW.conflict_count > 0
BEGIN
    SELECT RAISE(
        ABORT,
        'sluice: upgrade blocked by conflicting bindings. Two or more bindings share the same (credential, LOWER(destination)) but differ on ports/protocols/header/template/env_var. Run "sluice binding list" on the old binary, merge or remove the conflicting rows, and then retry the upgrade.'
    );
END;

INSERT INTO _sluice_binding_conflict_check_nocase (conflict_count)
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

DROP TRIGGER _sluice_binding_conflict_check_nocase_raise;
DROP TABLE _sluice_binding_conflict_check_nocase;

-- Pre-existing case-variant duplicates that are byte-identical on the
-- behavioral columns are collapsed to the lowest-id row per
-- (credential, LOWER(destination)) group. Paired auto-created allow rules
-- from the discarded bindings are cleaned up with the same rule of thumb,
-- keyed on (source, LOWER(destination)).
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

-- Drop the case-sensitive index from 000005 before creating the new
-- case-insensitive one so existing databases pick up the new behavior.
DROP INDEX IF EXISTS idx_bindings_credential_destination;

CREATE UNIQUE INDEX IF NOT EXISTS idx_bindings_credential_destination
    ON bindings(credential, LOWER(destination));
