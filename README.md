# WindowsCleanup - PowerShell

A conservative PowerShell cleanup workflow for old temporary files on Windows. It is designed to inspect authorized temporary folders, report candidates, move them to quarantine, restore them safely, and expire old quarantine runs.

## Features

- Simulates cleanup by default
- Scans only the effective user TEMP folder, `%LOCALAPPDATA%\Temp`, and `%WINDIR%\Temp`
- Moves eligible files to a per-run quarantine when `-Apply` is used
- Uses age, extension, name, file count, and size limits
- Protects documents, credentials, databases, keys, executables, installers, scripts, and files without extensions
- Rejects UNC paths, volume roots, path traversal, and reparse points
- Uses SHA-256 validation before and after quarantine moves
- Keeps a structured manifest, manifest hash, summary, completion marker, and transcript
- Supports safe restore without overwriting an existing file
- Expires complete runs only after the retention period
- Prevents simultaneous cleanup, restore, and expiration operations with a per-user mutex
- Does not change ACLs, ownership, attributes, power settings, or Windows configuration

## How It Works

The workflow has four independent operations:

1. `windows-clean.ps1` discovers old temporary files and simulates the requested action unless `-Apply` is supplied.
2. Without `-Permanent`, `-Apply` moves candidates to quarantine and verifies the destination with size and SHA-256 checks.
3. `windows-clean-restore.ps1` validates a run manifest and restores eligible quarantined files without overwriting existing files.
4. `windows-clean-expire.ps1` removes complete, validated run directories after the retention period. `windows-clean-purge.ps1` is a compatibility wrapper for the same operation.

The common module, `WindowsCleanup.Common.psm1`, centralizes path normalization, root validation, reparse-point checks, mutex handling, run-id validation, and manifest record creation.

Each run is stored below:

```text
%LOCALAPPDATA%\WindowsCleanup\Runs\<runId>\
    cleanup.log
    manifest.csv
    manifest.csv.sha256
    summary.json
    completed.json
    Quarantine\
        <RootName>\
            <RelativePath>
```

## Requirements

- Windows
- Windows PowerShell 5.1 or PowerShell 7+
- Administrator privileges are not required
- No production modules or Internet access are required
- Pester is optional and used only for tests

## Security Model

The project uses a deny-by-default model:

- Paths are expanded and normalized before validation.
- Only the three configured temporary locations are considered.
- Roots that are UNC paths, volume roots, forbidden system roots, reparse points, or overlapping the audit area are rejected.
- Directory traversal uses an explicit queue and does not enqueue reparse points.
- Protected extensions, sensitive names, and files without extensions are excluded.
- Candidate count and total size are limited per execution.
- `Move-Item` and `Remove-Item` use `-LiteralPath` and destructive operations are guarded by `ShouldProcess`.
- A shared mutex prevents concurrent cleanup, restore, and expiration for the same user.
- Runtime audit artifacts are kept outside the repository.

## Security Limitations

File paths and hashes cannot provide complete atomic protection against a local process that changes NTFS objects between validation and operation. Hard links are not explicitly identified. A sidecar SHA-256 detects accidental manifest changes but is not an authenticated signature if the same actor can modify both files. Test results do not replace a controlled trial on the target Windows PowerShell version.

## Usage

Open PowerShell in the project directory:

```powershell
Set-Location 'C:\path\to\windows-clean'
```

### Execution Policy

If PowerShell blocks script execution, allow scripts for the current session only:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

This change is discarded when the PowerShell window is closed.

### Safe Simulation

The default mode only reports candidates and creates audit artifacts:

```powershell
.\windows-clean.ps1 -OlderThanDays 30 -Verbose
```

Native `WhatIf` simulation of the apply path:

```powershell
.\windows-clean.ps1 -Apply -WhatIf -OlderThanDays 30
```

### Quarantine Simulation

```powershell
.\windows-clean.ps1 -Apply -WhatIf -OlderThanDays 30 -MaxFiles 100 -MaxSizeGB 1
```

A real quarantine requires `-Apply` without `-WhatIf`; review the generated manifest first. The public examples in this README intentionally do not perform real file changes.

### Restore Simulation

```powershell
.\windows-clean-restore.ps1 -ManifestPath "$env:LOCALAPPDATA\WindowsCleanup\Runs\<runId>\manifest.csv" -WhatIf
```

The manifest must remain inside its original run directory. Restore validates the completion marker, manifest hash, paths, reparse points, file size, and SHA-256 before proceeding.

### Expiration Simulation

```powershell
.\windows-clean-expire.ps1 -RetentionDays 14
```

The default mode only reports eligible complete runs. The compatibility wrapper has the same safe default:

```powershell
.\windows-clean-purge.ps1 -RetentionDays 14 -WhatIf
```

### Permanent Deletion Simulation

Permanent deletion is irreversible and should not be used as a routine cleanup method. It requires at least 60 days and is limited to `.tmp` and `.temp` files:

```powershell
.\windows-clean.ps1 -Apply -Permanent -OlderThanDays 60 -WhatIf -MaxFiles 100 -MaxSizeGB 1
```

## Parameters

`windows-clean.ps1` supports `-Apply`, `-OlderThanDays`, `-MaxFiles`, `-MaxSizeGB`, `-Permanent`, and `-IncludeUnknownExtensions`. Unknown extensions require at least 60 days and are never allowed with `-Permanent`.

`windows-clean-restore.ps1` requires `-ManifestPath` and supports `-Apply`.

`windows-clean-expire.ps1` and `windows-clean-purge.ps1` support `-RetentionDays` and `-Apply`.

All operational scripts support the standard `-WhatIf` and `-Confirm` parameters.

## Exit Codes

- `0`: successful operation, simulation, or nothing to do
- `1`: operational failure, partial failure, or incomplete processing
- `2`: invalid argument, unsafe configuration, invalid manifest, or failed security validation

## Troubleshooting

- Access denied under `%WINDIR%\Temp` is expected without elevation. The scripts skip inaccessible items and do not change permissions.
- A run without `completed.json` is preserved and is not eligible for expiration or restore.
- A changed manifest, sidecar hash, or completion marker is rejected.
- A busy mutex means another WindowsCleanup operation is active for the current user.
- A `QuarantinedAfterFailure` record requires manual review and valid integrity data before restore.
- If the terminal returns code `1`, inspect the transcript and summary for the affected run.
- PSScriptAnalyzer and Pester are development tools and are not required to run the cleanup scripts.

## Testing

Tests use `TestDrive`, artificial paths, and static inspection. They do not modify real TEMP, Windows TEMP, the user profile, or `%LOCALAPPDATA%\WindowsCleanup`:

```powershell
Invoke-Pester -Path .\tests\WindowsCleanup.Tests.ps1
```

Run static analysis when PSScriptAnalyzer is installed:

```powershell
Invoke-ScriptAnalyzer -Path . -Recurse
```

The test suite is compatible with the available Pester 3.4.0 syntax. Run an additional smoke test in Windows PowerShell 5.1 before production use.

## Repository Hygiene

Do not commit cleanup logs, manifests, summaries, completion markers, quarantine files, credentials, tokens, keys, personal paths, or data from `%LOCALAPPDATA%\WindowsCleanup`. These files are excluded by `.gitignore`.

## Contributions

Keep pull requests focused and security-oriented. Add isolated tests for path, reparse-point, manifest, concurrency, and `ShouldProcess` behavior. Do not weaken quarantine, validation, confirmation, or retention protections without documenting the security trade-off. Do not include real user data in issues, tests, or pull requests.

## License

MIT. See [LICENSE](LICENSE).
