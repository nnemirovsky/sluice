# Privacy policy

sluice runs on infrastructure you control. The project operates no server and sluice collects no telemetry. Nothing is sent to the author.

## What it reads

- All network traffic from the agent it guards, including HTTPS, which it decrypts with its own CA to inject credentials, apply policy and redact responses.
- MCP tool names, arguments and results that pass through its gateway.
- Your credentials, from the provider you configure: its age vault, environment variables, HashiCorp Vault, 1Password, Bitwarden, KeePass or gopass.
- Its policy, from `sluice.db` and any TOML file you import.

## What it writes

- `sluice.db` (or the `--db` path): policy rules, credential bindings and metadata, MCP upstreams with their `--env` values, approval channel settings including webhook secrets, credential pools and their health. Mode 0600.
- `audit.jsonl` (or the `--audit` path): one line per connection, tool call, approval, denial and injection, with destination, port, protocol, tool name, verdict and the credential name used. Never the credential value. Mode 0600.
- `~/.sluice/` (or `$SLUICE_VAULT_DIR`): the age key `vault-key.txt`, encrypted credentials under `credentials/`, and the CA `ca-cert.pem` and `ca-key.pem`. Directories 0700, keys and credentials 0600.
- Inside the agent container: phantom tokens in a marked block of the agent's env file, such as `~/.openclaw/.env`, the MCP gateway entry in the agent's config, and on a macOS VM the sluice CA in the guest keychain.
- Refreshed OAuth tokens back to the vault.

## Where it sends data

- **The destinations the agent connects to**, with phantom tokens replaced by the real credentials bound to that destination.
- **Telegram**, if you configure a bot: approval requests (destination, port, protocol, and for MCP calls the tool name and its arguments), pool and failover notices, and replies to your commands. Credential values you send to the bot are deleted from the chat.
- **Your webhook URL**, if you configure one: the same approval requests, signed with your webhook secret.
- **Your credential provider**, to read and update secrets.

sluice keeps the audit log and its database until you delete them.

## Contact

Questions go to [GitHub issues](https://github.com/nnemirovsky/sluice/issues).
