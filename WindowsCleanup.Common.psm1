Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function ConvertTo-NormalizedPath {
    param([Parameter(Mandatory)][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { throw 'O caminho não pode estar vazio.' }
    $expanded = [Environment]::ExpandEnvironmentVariables($Path)
    return ([IO.Path]::GetFullPath($expanded)).TrimEnd('\')
}

function Test-IsLocalFileSystemPath {
    param([Parameter(Mandatory)][string]$Path)
    if (-not [IO.Path]::IsPathRooted($Path) -or $Path.StartsWith('\\')) { return $false }
    $root = [IO.Path]::GetPathRoot($Path)
    return $Path.TrimEnd('\') -ne $root.TrimEnd('\')
}

function Test-DescendantPath {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Root)
    $normalizedPath = ConvertTo-NormalizedPath $Path
    $normalizedRoot = ConvertTo-NormalizedPath $Root
    $prefix = $normalizedRoot + '\'
    return $normalizedPath.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)
}

function Test-NoReparsePointInExistingParents {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$StopAtRoot
    )
    $stop = ConvertTo-NormalizedPath $StopAtRoot
    $currentPath = Split-Path -Parent (ConvertTo-NormalizedPath $Path)
    while (-not [string]::IsNullOrWhiteSpace($currentPath)) {
        $current = ConvertTo-NormalizedPath $currentPath
        if (Test-Path -LiteralPath $current -PathType Container) {
            $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return $false }
        }
        if ($current -ieq $stop) { return $true }
        $parent = Split-Path -Parent $current
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -ieq $current) { break }
        $currentPath = $parent
    }
    return $false
}

function Test-ValidRunId {
    param([Parameter(Mandatory)][string]$RunId)
    return $RunId -cmatch '^\d{8}-\d{9}-[0-9a-fA-F]{8}$'
}

function Enter-WindowsCleanupMutex {
    param([ValidateRange(0, 30)][int]$TimeoutSeconds = 0)
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $sid = $identity.User.Value
    $mutex = New-Object Threading.Mutex($false, "Local\WindowsCleanup-$sid")
    $acquired = $false
    try {
        try {
            $acquired = $mutex.WaitOne([TimeSpan]::FromSeconds($TimeoutSeconds))
        }
        catch [Threading.AbandonedMutexException] {
            $acquired = $true
            Write-Warning 'Foi encontrado um mutex abandonado. A execução anterior pode ter terminado inesperadamente.'
        }
        if (-not $acquired) {
            $mutex.Dispose()
            throw 'Já existe outra operação WindowsCleanup em execução para este utilizador.'
        }
        return [pscustomobject]@{ Mutex = $mutex; Acquired = $true }
    }
    catch {
        if (-not $acquired) { $mutex.Dispose() }
        throw
    }
}

function Exit-WindowsCleanupMutex {
    param([Parameter(Mandatory)][psobject]$Lock)
    if ($null -eq $Lock) { return }
    try {
        if ($Lock.Acquired -and $null -ne $Lock.Mutex) {
            $Lock.Mutex.ReleaseMutex() | Out-Null
        }
    }
    catch {
        Write-Warning "Não foi possível libertar o mutex: $($_.Exception.Message)"
    }
    finally {
        if ($null -ne $Lock.Mutex) { $Lock.Mutex.Dispose() }
    }
}

function Get-WindowsCleanupAuthorizedRoots {
    $definitions = @(
        [pscustomobject]@{ Name = 'UserTemp'; Path = $env:TEMP },
        [pscustomobject]@{ Name = 'LocalAppDataTemp'; Path = (Join-Path $env:LOCALAPPDATA 'Temp') },
        [pscustomobject]@{ Name = 'WindowsTemp'; Path = (Join-Path $env:WINDIR 'Temp') }
    )
    $seen = @{}
    foreach ($definition in $definitions) {
        if ([string]::IsNullOrWhiteSpace($definition.Path)) { continue }
        $path = ConvertTo-NormalizedPath $definition.Path
        if (-not (Test-IsLocalFileSystemPath $path)) { continue }
        if (-not (Test-Path -LiteralPath $path -PathType Container)) { continue }
        $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
        $key = $path.ToLowerInvariant()
        if (-not $seen.ContainsKey($key)) {
            $seen[$key] = [pscustomobject]@{ Name = $definition.Name; Path = $path }
        }
    }
    return @($seen.Values | Sort-Object Path)
}

function Test-WindowsCleanupAuthorizedRoot {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-IsLocalFileSystemPath $Path)) { return $false }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    return ($item.PSIsContainer -and (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0))
}

function New-WindowsCleanupManifestRecord {
    param(
        [Parameter(Mandatory)][string]$RunId,
        [Parameter(Mandatory)][string]$RootName,
        [Parameter(Mandatory)][string]$RootPath,
        [Parameter(Mandatory)][string]$RelativePath,
        [Parameter(Mandatory)][string]$OriginalPath,
        [AllowNull()][string]$QuarantinePath,
        [Parameter(Mandatory)][Int64]$Length,
        [AllowNull()][string]$Sha256,
        [AllowNull()][datetime]$LastWriteTimeUtc,
        [Parameter(Mandatory)][string]$Action,
        [Parameter(Mandatory)][string]$Status,
        [AllowNull()][string]$Error
    )
    $lastWrite = $null
    if ($null -ne $LastWriteTimeUtc) { $lastWrite = $LastWriteTimeUtc.ToString('o', [Globalization.CultureInfo]::InvariantCulture) }
    return [pscustomobject][ordered]@{
        SchemaVersion = 1; RunId = $RunId; RootName = $RootName; RootPath = $RootPath; RelativePath = $RelativePath
        OriginalPath = $OriginalPath; QuarantinePath = $QuarantinePath; Length = $Length; Sha256 = $Sha256
        LastWriteTimeUtc = $lastWrite; OperationUtc = (Get-Date).ToUniversalTime().ToString('o', [Globalization.CultureInfo]::InvariantCulture)
        Action = $Action; Status = $Status; Error = $Error
    }
}

Export-ModuleMember -Function ConvertTo-NormalizedPath, Test-IsLocalFileSystemPath, Test-DescendantPath, Test-NoReparsePointInExistingParents, Test-ValidRunId, Enter-WindowsCleanupMutex, Exit-WindowsCleanupMutex, New-WindowsCleanupManifestRecord, Get-WindowsCleanupAuthorizedRoots, Test-WindowsCleanupAuthorizedRoot
