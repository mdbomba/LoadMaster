# WUG LoadMaster Configuration Management Status

Last updated: 2026-09-01

## Requested Outcome

WhatsUp Gold on `wug` (`10.0.0.40`) should use the LoadMaster API to back up
`10.0.0.90`, show a genuine backup and execution record in the Configuration
Management interface, retain the exact restorable payload, and provide a
controlled REST restore workflow. LoadMaster SSH must not be used.

## Current Live State

- WUG device `10.0.0.90` exists as device ID `60` and is Up.
- WUG Configuration Management is licensed and initialized.
- WUG PowerShell action ID `5` is named `LoadMaster 10.0.0.90 REST Backup`.
- WUG recurring action ID `1` invokes action ID `5` daily at `02:15` WUG time.
- The action runs on `wug` and calls LoadMaster API v2 `cmd=backup` over HTTPS.
- The action writes an exact `.backup`, an uncompressed `.tar`, an extracted
  directory, text rendering, manifest, and SHA-256 under:
  `C:\ProgramData\Ipswitch\WhatsUp\LoadMasterBackups\10.0.0.90`.
- A live test succeeded and extracted 56 files.
- The action also creates a custom WUG archive with key
  `loadmaster-rest-backup` for device ID `60`.
- All exploratory SSH credentials, CLI profiles, and scripts were removed.
- No Linux cron job or Linux-side WUG backup remains.

## Important Limitation

The current action is an interim integration, not the requested final WUG
Configuration Management device method/template.

The archive created with `CMArchive/saveArchive`:

- Has `Custom=true`.
- Contains an extracted text rendering rather than the exact backup payload.
- Does not have WUG task/script provenance such as `ConfigTaskID`,
  `ConfigTaskName`, or `ConfigScriptName`.
- Does not create a `CMTaskHistory` execution record.
- Cannot be restored correctly with WUG's generic Restore button. That button
  expects a CLI upload workflow and has no LoadMaster restore scope (`1-15`).

The exact restorable LoadMaster `.backup` exists on the WUG filesystem, but it
is not represented as a binary-aware Configuration Management backup record.

## Security Note

The live WUG action currently contains reusable LoadMaster and WUG credentials
because the WUG action service cannot authenticate implicitly to the local
`CMArchive` endpoint. The checked-in source file contains placeholders only.
Move these secrets to a supported protected WUG credential mechanism or a
dedicated service-account secret store before production use.

## Next Work

1. Research the supported WUG extension point for a REST-based Configuration
   Management device method/template. Native task and system scripts are
   SSH/Telnet-oriented, so this may require a vendor adapter rather than the
   custom task-script language.
2. Create a persistent `CMTask` and device association so WUG generates real
   `CMTaskHistory` and task provenance instead of fabricating archive metadata.
3. Store the exact LoadMaster API v2 `data` value in a durable record with
   explicit encoding, checksum, source, and restore-scope metadata.
4. Implement restore as a separate confirmed action that retrieves the exact
   payload and calls LoadMaster API v2 `cmd=restore`, with an explicitly chosen
   restore type from `1` through `15`.
5. Do not use WUG's generic `CMArchive/restoreArchive` for LoadMaster data.
6. Validate backup and restore against a disposable LoadMaster before enabling
   production restore.
7. Replace or remove the interim action and custom archive after the genuine
   task/template implementation is verified.

## Saved Source

The redacted source corresponding to the interim action is:

`loadmaster-sample-scripts/wug-loadmaster-rest-backup-action.ps1`

Do not populate its placeholders in Git.
