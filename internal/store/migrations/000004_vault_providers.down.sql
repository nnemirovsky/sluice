-- SQLite does not support DROP COLUMN before 3.35.0. Recreate the table
-- without the new columns. This is the standard SQLite migration pattern.

CREATE TABLE config_backup AS SELECT
    id, default_verdict, timeout_sec, vault_provider, vault_dir, vault_providers,
    vault_hashicorp_addr, vault_hashicorp_mount, vault_hashicorp_prefix,
    vault_hashicorp_auth, vault_hashicorp_token,
    vault_hashicorp_role_id, vault_hashicorp_secret_id,
    vault_hashicorp_role_id_env, vault_hashicorp_secret_id_env
FROM config;
-- Drops: vault_1password_token, vault_1password_vault, vault_1password_field,
-- vault_bitwarden_token, vault_bitwarden_org_id, vault_keepass_path,
-- vault_keepass_key_file, vault_gopass_store

DROP TABLE config;

CREATE TABLE config (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    default_verdict TEXT NOT NULL DEFAULT 'deny' CHECK(default_verdict IN ('allow', 'deny', 'ask')),
    timeout_sec INTEGER NOT NULL DEFAULT 120,
    vault_provider TEXT NOT NULL DEFAULT 'age',
    vault_dir TEXT,
    vault_providers TEXT,
    vault_hashicorp_addr TEXT,
    vault_hashicorp_mount TEXT DEFAULT 'secret',
    vault_hashicorp_prefix TEXT,
    vault_hashicorp_auth TEXT DEFAULT 'token',
    vault_hashicorp_token TEXT,
    vault_hashicorp_role_id TEXT,
    vault_hashicorp_secret_id TEXT,
    vault_hashicorp_role_id_env TEXT,
    vault_hashicorp_secret_id_env TEXT
);

INSERT INTO config SELECT * FROM config_backup;
DROP TABLE config_backup;
