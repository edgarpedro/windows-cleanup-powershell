#requires -Version 5.1

BeforeAll {
    $script:repositoryRoot = Split-Path `
        -Path $PSScriptRoot `
        -Parent

    $script:modulePath = Join-Path `
        $script:repositoryRoot `
        'WindowsCleanup.Common.psm1'

    $script:cleanPath = Join-Path `
        $script:repositoryRoot `
        'windows-clean.ps1'

    $script:restorePath = Join-Path `
        $script:repositoryRoot `
        'windows-clean-restore.ps1'

    $script:expirePath = Join-Path `
        $script:repositoryRoot `
        'windows-clean-expire.ps1'

    $script:purgePath = Join-Path `
        $script:repositoryRoot `
        'windows-clean-purge.ps1'

    $requiredFiles = @(
        $script:modulePath
        $script:cleanPath
        $script:restorePath
        $script:expirePath
        $script:purgePath
    )

    foreach ($requiredFile in $requiredFiles) {
        if (-not (Test-Path -LiteralPath $requiredFile -PathType Leaf)) {
            throw "Required project file not found: $requiredFile"
        }
    }
}

Describe 'WindowsCleanup.Common' {
    BeforeAll {
        Import-Module `
            -Name $script:modulePath `
            -Force `
            -ErrorAction Stop

        $reparseSupported = $false
        $reparseSkipReason = 'The test environment does not support junction creation.'
        $target = Join-Path $TestDrive 'probe-target'
        $reparseLink = Join-Path $TestDrive 'probe-link'
        New-Item -ItemType Directory -Path $target | Out-Null
        try {
            New-Item -ItemType Junction -Path $reparseLink -Target $target -ErrorAction Stop | Out-Null
            $reparseSupported = -not (Test-NoReparsePointInExistingParents -Path (Join-Path $reparseLink 'x.tmp') -StopAtRoot $TestDrive)
            if (-not $reparseSupported) { $reparseSkipReason = 'TestDrive created a junction but did not expose it as a reparse point.' }
        } catch { $reparseSkipReason = $_.Exception.Message }
    }

    AfterAll {
        Remove-Item -LiteralPath 'env:WINDOWSCLEANUP_TEST_ROOT' -ErrorAction SilentlyContinue
        Remove-Module -Name 'WindowsCleanup.Common' -Force -ErrorAction SilentlyContinue
    }

    It 'normalizes an absolute path and expands environment variables' {
        $env:WINDOWSCLEANUP_TEST_ROOT = $TestDrive
        $result = ConvertTo-NormalizedPath '%WINDOWSCLEANUP_TEST_ROOT%\folder\..\file.tmp'
        $result | Should -Be (Join-Path $TestDrive 'file.tmp')
    }

    It 'rejects UNC paths, relative paths and volume roots' {
        (Test-IsLocalFileSystemPath '\\server\share\file.tmp') | Should -Be $false
        (Test-IsLocalFileSystemPath 'relative\file.tmp') | Should -Be $false
        (Test-IsLocalFileSystemPath ([IO.Path]::GetPathRoot($TestDrive))) | Should -Be $false
    }

    It 'detects descendants without prefix collisions' {
        (Test-DescendantPath (Join-Path $TestDrive 'root\child.tmp') (Join-Path $TestDrive 'root')) | Should -Be $true
        (Test-DescendantPath (Join-Path $TestDrive 'root-other\child.tmp') (Join-Path $TestDrive 'root')) | Should -Be $false
        (Test-DescendantPath (Join-Path $TestDrive 'root') (Join-Path $TestDrive 'root')) | Should -Be $false
    }

    It 'validates existing parents up to the requested root' {
        $root = Join-Path $TestDrive 'root'
        $nested = Join-Path $root 'a\b\file.tmp'
        New-Item -ItemType Directory -Path (Split-Path $nested -Parent) -Force | Out-Null
        (Test-NoReparsePointInExistingParents -Path $nested -StopAtRoot $root) | Should -Be $true
        (Test-NoReparsePointInExistingParents -Path $nested -StopAtRoot (Join-Path $TestDrive 'other')) | Should -Be $false
    }

    It 'validates run ids' {
        (Test-ValidRunId '20260828-123456789-a1B2c3D4') | Should -Be $true
        (Test-ValidRunId '20260828-12345678-a1b2c3d4') | Should -Be $false
        (Test-ValidRunId '20260828-123456789-xyz12345') | Should -Be $false
    }

    It 'acquires and releases the shared mutex' {
        $lock = Enter-WindowsCleanupMutex -TimeoutSeconds 0
        try { $lock.Acquired | Should -Be $true } finally { Exit-WindowsCleanupMutex $lock }
        $second = Enter-WindowsCleanupMutex -TimeoutSeconds 0
        try { $second.Acquired | Should -Be $true } finally { Exit-WindowsCleanupMutex $second }
    }

    It 'creates ordered SchemaVersion 1 ISO records' {
        $file = New-Item -ItemType File -Path (Join-Path $TestDrive 'item.tmp')
        $record = New-WindowsCleanupManifestRecord -RunId '20260828-123456789-a1b2c3d4' -RootName 'TestRoot' -RootPath $TestDrive -RelativePath 'item.tmp' -OriginalPath $file.FullName -QuarantinePath (Join-Path $TestDrive 'q\item.tmp') -Length 0 -Sha256 ('A' * 64) -LastWriteTimeUtc $file.LastWriteTimeUtc -Action 'Quarantine' -Status 'Simulated' -Error $null
        $expectedNames = @('SchemaVersion', 'RunId', 'RootName', 'RootPath', 'RelativePath', 'OriginalPath', 'QuarantinePath', 'Length', 'Sha256', 'LastWriteTimeUtc', 'OperationUtc', 'Action', 'Status', 'Error')
        # Joined to keep the ordered comparison immune to pipeline unrolling of the property collection.
        (@($record.PSObject.Properties.Name) -join ',') | Should -Be ($expectedNames -join ',')
        $record.SchemaVersion | Should -Be 1
        $record.LastWriteTimeUtc | Should -Match 'Z$'
        $record.OperationUtc | Should -Match 'Z$'
    }

    It 'deduplicates authorized roots by path in implementation' {
        (Get-Content -LiteralPath $script:modulePath -Raw) | Should -Match 'ContainsKey\(\$key\)'
        (Get-Content -LiteralPath $script:cleanPath -Raw) | Should -Match 'WindowsCleanup.Common.psm1'
    }

    It 'skips reparse points when supported by the filesystem' {
        # The junction probe only exists after the Run phase starts, so the guard cannot live in -Skip.
        if (-not $reparseSupported) { Set-ItResult -Skipped -Because $reparseSkipReason }
        (Test-NoReparsePointInExistingParents -Path (Join-Path $reparseLink 'x.tmp') -StopAtRoot $TestDrive) | Should -Be $false
    }
}

Describe 'WindowsCleanup script contracts' {
    It 'keeps the operational scripts independent and imports the common module' {
        $htmlPattern = ([char]60) + 'br' + ([char]62) + '|&' + 'lt;|&' + 'gt;|&' + 'amp;'
        foreach ($path in @($script:cleanPath, $script:restorePath, $script:expirePath)) {
            (Test-Path -LiteralPath $path -PathType Leaf) | Should -Be $true
            (Get-Content -LiteralPath $path -Raw) | Should -Match 'WindowsCleanup.Common.psm1'
            ([regex]::IsMatch((Get-Content -LiteralPath $path -Raw), $htmlPattern)) | Should -Be $false
        }
        (Get-Content -LiteralPath $script:purgePath -Raw) | Should -Match 'windows-clean-expire.ps1'
        (Get-Content -LiteralPath $script:purgePath -Raw) | Should -Not -Match 'Remove-Item'
    }

    It 'uses literal paths and does not force Move-Item' {
        foreach ($path in @($script:cleanPath, $script:restorePath, $script:expirePath, $script:purgePath)) {
            $content = Get-Content -LiteralPath $path -Raw
            ([regex]::IsMatch($content, 'Move-Item[^\r\n]*-Force')) | Should -Be $false
            ([regex]::IsMatch($content, 'Remove-Item\s+-Path')) | Should -Be $false
        }
    }

    It 'contains the required safety policies' {
        $clean = Get-Content -LiteralPath $script:cleanPath -Raw
        $clean | Should -Match 'ValidateRange\(7, 3650\)'
        $clean | Should -Match 'ValidateRange\(1, 50000\)'
        $clean | Should -Match 'ValidateRange\(1, 20\)'
        $clean | Should -Match 'Permanent'
        $clean | Should -Match 'IncludeUnknownExtensions'
        $clean | Should -Match 'ShouldProcess'
        $clean | Should -Match 'QuarantinedAfterFailure'
    }

    It 'requires integrity and completion artefacts for restore and expire' {
        foreach ($path in @($script:restorePath, $script:expirePath)) {
            $content = Get-Content -LiteralPath $path -Raw
            $content | Should -Match 'manifest.csv'
            $content | Should -Match 'manifest.csv.sha256'
            $content | Should -Match 'completed.json'
            $content | Should -Match 'SHA-256|ManifestSha256'
        }
    }
}
