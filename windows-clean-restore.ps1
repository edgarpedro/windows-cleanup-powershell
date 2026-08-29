#requires -Version 5.1
<##
.SYNOPSIS
Validates and simulates restoration of quarantined files.
.DESCRIPTION
Restoration requires a valid run manifest, integrity hash, completion marker, and a non-existing authorized destination.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High', PositionalBinding = $false)]
param(
	[Parameter(Mandatory)]
	[ValidateNotNullOrEmpty()]
	[string]$ManifestPath,

	[switch]$Apply
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'WindowsCleanup.Common.psm1') -Force

$basePath = Join-Path $env:LOCALAPPDATA 'WindowsCleanup'
$normalizedBasePath = [IO.Path]::GetFullPath($basePath).TrimEnd('\') + '\'
$normalizedManifestPath = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $ManifestPath -ErrorAction Stop).Path)
if (-not $normalizedManifestPath.StartsWith($normalizedBasePath, [StringComparison]::OrdinalIgnoreCase)) {
	throw "O manifesto tem de estar dentro de '$basePath'."
}
$manifestName = [IO.Path]::GetFileName($normalizedManifestPath)
$runPath = [IO.Path]::GetDirectoryName($normalizedManifestPath)
$runName = [IO.Path]::GetFileName($runPath)
$runsRoot = [IO.Path]::GetFullPath((Join-Path $basePath 'Runs')).TrimEnd('\') + '\'
$runNamePattern = '^\d{8}-\d{9}-[0-9a-f]{8}$'
if ($manifestName -cne 'manifest.csv' -or [IO.Path]::GetDirectoryName($runPath).TrimEnd('\') -ine $runsRoot.TrimEnd('\') -or $runName -notmatch $runNamePattern) {
	throw 'O manifesto tem de estar exatamente em WindowsCleanup\Runs\<runId>\manifest.csv.'
}
$quarantinePath = [IO.Path]::GetFullPath((Join-Path $runPath 'Quarantine')).TrimEnd('\') + '\'
$quarantineRoot = $quarantinePath.TrimEnd('\')
$manifestHashPath = Join-Path $runPath 'manifest.csv.sha256'
$completedPath = Join-Path $runPath 'completed.json'
$allowedRoots = @(
	[Environment]::ExpandEnvironmentVariables($env:TEMP),
	(Join-Path $env:LOCALAPPDATA 'Temp'),
	(Join-Path $env:WINDIR 'Temp')
) | Where-Object { $_ } | ForEach-Object { [IO.Path]::GetFullPath($_).TrimEnd('\') + '\' } | Select-Object -Unique
$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$currentUserSid = $currentIdentity.User.Value
$mutex = New-Object Threading.Mutex($false, "Local\WindowsCleanup-$currentUserSid")
$mutexAcquired = $false
$restoreExitCode = 0

try {
	try {
		$mutexAcquired = $mutex.WaitOne(0)
	}
	catch [Threading.AbandonedMutexException] {
		$mutexAcquired = $true
		Write-Warning 'Foi encontrado um mutex abandonado. A execução anterior pode ter terminado inesperadamente.'
	}
	if (-not $mutexAcquired) { throw 'Já existe outra operação WindowsCleanup em execução para este utilizador.' }
	$completedItem = Get-Item -LiteralPath $completedPath -Force -ErrorAction Stop
	if (($completedItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'O marcador de conclusão é um reparse point.' }
	$completion = Get-Content -LiteralPath $completedPath -Raw -ErrorAction Stop | ConvertFrom-Json
	if ($completion.RunId -cne $runName -or [int]$completion.ExitCode -ne 0 -or [int]$completion.SchemaVersion -ne 1) { throw 'A execução não está concluída com sucesso.' }
	$completionHash = [string]$completion.ManifestSha256
	$manifestHashItem = Get-Item -LiteralPath $manifestHashPath -Force -ErrorAction Stop
	if (($manifestHashItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'O hash do manifesto é um reparse point.' }
	$expectedManifestHash = (Get-Content -LiteralPath $manifestHashPath -Raw -ErrorAction Stop).Trim().ToUpperInvariant()
	if ($expectedManifestHash -notmatch '^[0-9A-F]{64}$') { throw 'Hash do manifesto inválido.' }
	$actualManifestHash = (Get-FileHash -LiteralPath $normalizedManifestPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToUpperInvariant()
	if ($actualManifestHash -cne $expectedManifestHash) { throw 'O manifesto foi alterado depois da operação de limpeza.' }
	if ([string]::IsNullOrWhiteSpace($completionHash) -or $completionHash.ToUpperInvariant() -cne $actualManifestHash) { throw 'O hash do manifesto não corresponde ao marcador de conclusão.' }

	if (-not $Apply) {
		Write-Warning 'MODO SIMULAÇÃO: nenhum ficheiro será restaurado. Use -Apply para executar o restauro.'
	}

$records = @(Import-Csv -LiteralPath $normalizedManifestPath -ErrorAction Stop)
$requiredColumns = @('OriginalPath', 'QuarantinePath', 'Length', 'Sha256', 'Action', 'Status')
if ($records.Count -eq 0) {
	Write-Host 'O manifesto não contém ficheiros para restaurar.'
}
else {
$actualColumns = @($records[0].PSObject.Properties.Name)
$missingColumns = @($requiredColumns | Where-Object { $_ -notin $actualColumns })
if ($missingColumns.Count -gt 0) {
	throw "Manifesto inválido. Colunas em falta: $($missingColumns -join ', ')"
}
$restored = 0
$skipped = 0
$failed = 0
$notProcessed = 0
$simulated = 0

foreach ($record in $records) {
	if ($record.Status -notin @('Success', 'QuarantinedAfterFailure') -or $record.Action -ne 'Quarantine') {
		$skipped++
		continue
	}

	try {
		if ([string]::IsNullOrWhiteSpace($record.QuarantinePath) -or [string]::IsNullOrWhiteSpace($record.OriginalPath)) {
			throw 'Manifesto sem caminho de origem ou de quarentena.'
		}
		$normalizedSource = [IO.Path]::GetFullPath($record.QuarantinePath)
		$normalizedOriginal = [IO.Path]::GetFullPath($record.OriginalPath)
		if (-not (Test-DescendantPath -Path $normalizedSource -Root $quarantinePath)) {
			throw 'QuarantinePath está fora da quarentena desta execução.'
		}
		$matchedOriginalRoot = $allowedRoots | Where-Object { Test-DescendantPath -Path $normalizedOriginal -Root $_ } | Select-Object -First 1
		if (-not $matchedOriginalRoot) {
			throw 'OriginalPath está fora das pastas temporárias autorizadas.'
		}
		if (-not (Test-NoReparsePointInExistingParents -Path $normalizedSource -StopAtRoot $quarantineRoot) -or
			-not (Test-NoReparsePointInExistingParents -Path $normalizedOriginal -StopAtRoot $matchedOriginalRoot)) {
			throw 'Foi encontrado um reparse point no percurso do ficheiro.'
		}
		if (-not (Test-Path -LiteralPath $normalizedSource -PathType Leaf)) {
			throw "Ficheiro em quarentena não encontrado: $normalizedSource"
		}
		if (Test-Path -LiteralPath $normalizedOriginal) {
			throw "O destino original já existe: $normalizedOriginal"
		}

		$source = Get-Item -LiteralPath $normalizedSource -Force -ErrorAction Stop
		if (($source.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
			throw "Ficheiro em quarentena é um reparse point: $normalizedSource"
		}
		$expectedLength = 0L
		if ([string]::IsNullOrWhiteSpace($record.Sha256)) {
			throw 'Manifesto sem SHA-256.'
		}
		$expectedHash = $record.Sha256.ToUpperInvariant()
		if ($expectedHash -notmatch '^[0-9A-F]{64}$') {
			throw 'Manifesto com SHA-256 inválido.'
		}
		if (-not [Int64]::TryParse($record.Length, [Globalization.NumberStyles]::Integer, [Globalization.CultureInfo]::InvariantCulture, [ref]$expectedLength) -or $expectedLength -lt 0) { throw 'Manifesto com tamanho inválido.' }
		if ($source.Length -ne $expectedLength) { throw 'O tamanho do ficheiro não corresponde ao manifesto.' }
		$actualHash = (Get-FileHash -LiteralPath $normalizedSource -Algorithm SHA256 -ErrorAction Stop).Hash.ToUpperInvariant()
		if ($actualHash -ne $expectedHash) { throw 'O SHA-256 do ficheiro não corresponde ao manifesto.' }

		$parent = Split-Path -Parent $normalizedOriginal
		$action = "Restaurar de '$normalizedSource'"
		if (-not $Apply) {
			$simulated++
			Write-Host "Simulação: $action -> $normalizedOriginal"
			continue
		}
		if ($PSCmdlet.ShouldProcess($normalizedOriginal, $action)) {
			New-Item -ItemType Directory -Path $parent -Force -Confirm:$false -ErrorAction Stop | Out-Null
			if (-not (Test-NoReparsePointInExistingParents -Path $normalizedOriginal -StopAtRoot $matchedOriginalRoot)) {
				throw 'Percurso original inseguro após a criação das pastas.'
			}
			Move-Item -LiteralPath $normalizedSource -Destination $normalizedOriginal -Confirm:$false -ErrorAction Stop
			if (Test-Path -LiteralPath $normalizedSource -PathType Leaf) { throw 'A origem ainda existe após o restauro.' }
			$restoredItem = Get-Item -LiteralPath $normalizedOriginal -Force -ErrorAction Stop
			if (($restoredItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $restoredItem.Length -ne $expectedLength) { throw 'O ficheiro restaurado falhou a validação de tamanho ou reparse point.' }
			if ((Get-FileHash -LiteralPath $normalizedOriginal -Algorithm SHA256 -ErrorAction Stop).Hash -ine $expectedHash) { throw 'O hash do ficheiro restaurado não corresponde ao manifesto.' }
			$restored++
		}
		else {
			$notProcessed++
		}
	}
	catch {
		$failed++
		Write-Warning ("Falha ao restaurar '{0}': {1}" -f $record.QuarantinePath, $_.Exception.Message)
	}
}

Write-Host "Ficheiros restaurados: $restored"
Write-Host "Restauros simulados: $simulated"
Write-Host "Registos ignorados: $skipped"
Write-Host "Operações não processadas: $notProcessed"
Write-Host "Ficheiros com erro: $failed"
if ($failed -gt 0) { $restoreExitCode = 1 }
}
}
catch {
	$restoreExitCode = 2
	Write-Error -Message "Validação do restauro falhou: $($_.Exception.Message)" -ErrorAction Continue
}
finally {
	if ($mutexAcquired) { $mutex.ReleaseMutex() | Out-Null }
	$mutex.Dispose()
}

exit $restoreExitCode
