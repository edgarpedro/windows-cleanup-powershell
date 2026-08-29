#requires -Version 5.1
<##
.SYNOPSIS
Simulates or applies conservative cleanup of authorized temporary folders.
.DESCRIPTION
Candidates are filtered and, with -Apply, moved to a per-run quarantine unless Permanent is explicitly selected.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
	[switch]$Apply,

	[ValidateRange(7, 3650)]
	[int]$OlderThanDays = 30,

	[ValidateRange(1, 50000)]
	[int]$MaxFiles = 5000,

	[ValidateRange(1, 20)]
	[int]$MaxSizeGB = 2,

	[switch]$Permanent,
	[switch]$IncludeUnknownExtensions
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'WindowsCleanup.Common.psm1') -Force

if ($Permanent -and -not $Apply) {
	Write-Warning 'Remoção permanente em simulação. Nenhum ficheiro será eliminado; use -Apply para executar.'
}
if ($Permanent -and $OlderThanDays -lt 60) {
	throw 'A remoção permanente exige OlderThanDays igual ou superior a 60.'
}
if ($Permanent -and $IncludeUnknownExtensions) {
	throw 'IncludeUnknownExtensions não pode ser combinado com Permanent.'
}
if ($IncludeUnknownExtensions -and $OlderThanDays -lt 60) {
	throw 'IncludeUnknownExtensions exige OlderThanDays igual ou superior a 60.'
}

$basePath = Join-Path $env:LOCALAPPDATA 'WindowsCleanup'
$runTimestamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmssfff', [Globalization.CultureInfo]::InvariantCulture)
$runId = '{0}-{1}' -f $runTimestamp, ([guid]::NewGuid().ToString('N').Substring(0, 8))
$runPath = Join-Path $basePath "Runs\$runId"
$quarantinePath = Join-Path $runPath 'Quarantine'
$logPath = Join-Path $runPath 'cleanup.log'
$manifestPath = Join-Path $runPath 'manifest.csv'
$cutoffUtc = (Get-Date).ToUniversalTime().AddDays(-$OlderThanDays)
$maxBytes = [int64]$MaxSizeGB * 1GB

$protectedExtensions = @(
	'.pst', '.ost', '.vhd', '.vhdx', '.iso', '.pfx', '.p12', '.pem', '.key', '.kdbx',
	'.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf',
	'.sqlite', '.db', '.mdf', '.ldf', '.bak', '.config', '.json', '.xml', '.ps1', '.psm1', '.reg',
	'.exe', '.dll', '.sys', '.com', '.msi', '.msp', '.msix', '.appx', '.cab', '.bat', '.cmd', '.vbs', '.js', '.wsf'
)
$temporaryExtensions = @('.tmp', '.temp', '.log', '.dmp', '.etl', '.cache', '.old')
$permanentDeleteExtensions = @('.tmp', '.temp')
$excludedNamePatterns = @(
	'*password*', '*credential*', '*secret*', '*token*', '*backup*', '*recovery*',
	'*certificate*', '*privatekey*', '*wallet*', '*database*'
)
$cleanupRoots = @(
	[pscustomobject]@{ Name = 'UserTemp'; Path = $env:TEMP },
	[pscustomobject]@{ Name = 'LocalAppDataTemp'; Path = (Join-Path $env:LOCALAPPDATA 'Temp') },
	[pscustomobject]@{ Name = 'WindowsTemp'; Path = (Join-Path $env:WINDIR 'Temp') }
)

$filesChecked = 0
$filesSelected = 0
$filesProcessed = 0
$filesFailed = 0
$filesWithIoError = 0
$filesExcluded = 0
$filesTooRecent = 0
$filesSkippedBySize = 0
$filesChangedBeforeProcessing = 0
$filesReparseDetected = 0
$bytesSelected = [int64]0
$bytesProcessed = [int64]0
$limitReached = $false
$exitCode = 0
$directoriesFailed = 0
$manifest = [System.Collections.Generic.List[object]]::new()
$transcriptStarted = $false
$manifestAction = if ($Permanent) { 'PermanentDelete' } else { 'Quarantine' }
$manifestHashPath = Join-Path $runPath 'manifest.csv.sha256'
$completedPath = Join-Path $runPath 'completed.json'
$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$currentUserSid = $currentIdentity.User.Value
$mutex = New-Object Threading.Mutex($false, "Local\WindowsCleanup-$currentUserSid")
$mutexAcquired = $false

function Test-ExcludedFile {
	param([Parameter(Mandatory)][System.IO.FileInfo]$File)
	$extension = $File.Extension.ToLowerInvariant()
	if ([string]::IsNullOrWhiteSpace($extension)) { return $true }
	if ($protectedExtensions -contains $extension) { return $true }
	if ($Permanent -and $permanentDeleteExtensions -notcontains $extension) { return $true }
	if (-not $IncludeUnknownExtensions -and $temporaryExtensions -notcontains $extension) { return $true }
	foreach ($pattern in $excludedNamePatterns) {
		if ($File.Name -ilike $pattern) { return $true }
	}
	return $false
}

function Get-SafeFiles {
	param([Parameter(Mandatory)][string]$Root)
	$queue = [System.Collections.Generic.Queue[string]]::new()
	$queue.Enqueue($Root)
	while ($queue.Count -gt 0 -and -not $script:limitReached) {
		$current = $queue.Dequeue()
		try {
			foreach ($directory in Get-ChildItem -LiteralPath $current -Directory -Force -ErrorAction Stop) {
				if (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) { $queue.Enqueue($directory.FullName) }
			}
			foreach ($file in @(Get-ChildItem -LiteralPath $current -File -Force -ErrorAction Stop | Sort-Object LastWriteTimeUtc, Length, FullName)) {
				$script:filesChecked++
				if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
				if ($file.LastWriteTimeUtc -ge $cutoffUtc) { $script:filesTooRecent++; continue }
				if (Test-ExcludedFile -File $file) { $script:filesExcluded++; continue }
				if ($script:filesSelected -ge $MaxFiles) {
					$script:limitReached = $true
					Write-Warning "Limite máximo de $MaxFiles ficheiros atingido."
					break
				}
				if (($script:bytesSelected + $file.Length) -gt $maxBytes) {
					$script:filesSkippedBySize++
					Write-Verbose "Ignorado pelo limite de tamanho: $($file.FullName)"
					continue
				}
				$script:filesSelected++
				$script:bytesSelected += $file.Length
				$file
			}
		}
		catch {
			$script:directoriesFailed++
			Write-Warning "Diretório ignorado: $current : $($_.Exception.Message)"
		}
	}
}

try {
	try {
		$mutexAcquired = $mutex.WaitOne(0)
	}
	catch [Threading.AbandonedMutexException] {
		$mutexAcquired = $true
		Write-Warning 'Foi encontrado um mutex abandonado. A execução anterior pode ter terminado inesperadamente.'
	}
	if (-not $mutexAcquired) { throw 'Já existe outra operação WindowsCleanup em execução para este utilizador.' }

	$normalizedRoots = @(foreach ($rootEntry in $cleanupRoots) {
		if ([string]::IsNullOrWhiteSpace($rootEntry.Path)) { continue }
		$normalizedPath = ConvertTo-NormalizedPath -Path $rootEntry.Path
		if (-not (Test-Path -LiteralPath $normalizedPath -PathType Container)) {
			Write-Warning "Raiz inexistente, ignorada: $normalizedPath"
			continue
		}
		[pscustomobject]@{ Name = $rootEntry.Name; Path = $normalizedPath }
	}) | Group-Object { $_.Path.ToLowerInvariant() } | ForEach-Object { $_.Group | Select-Object -First 1 }
	$normalizedRoots = @($normalizedRoots)
	if ($normalizedRoots.Count -eq 0) { throw 'Não foi encontrada nenhuma pasta temporária válida para análise.' }

	$forbiddenRoots = @($env:SystemDrive + '\', $env:WINDIR, $env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:USERPROFILE) |
		Where-Object { $_ } | ForEach-Object { ConvertTo-NormalizedPath -Path $_ }
	foreach ($rootEntry in $normalizedRoots) {
		$rootItem = Get-Item -LiteralPath $rootEntry.Path -Force -ErrorAction Stop
		if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Raiz é um reparse point: $($rootEntry.Path)" }
		if (-not (Test-IsLocalFileSystemPath -Path $rootEntry.Path)) { throw "Caminho não autorizado: $($rootEntry.Path)" }
		if ($forbiddenRoots -icontains $rootEntry.Path) { throw "Caminho crítico recusado: $($rootEntry.Path)" }
		$normalizedBasePath = ConvertTo-NormalizedPath -Path $basePath
		$basePrefix = $normalizedBasePath.TrimEnd('\') + '\'
		$rootPrefix = $rootEntry.Path.TrimEnd('\') + '\'
		if ($normalizedBasePath.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase) -or $rootEntry.Path.StartsWith($basePrefix, [StringComparison]::OrdinalIgnoreCase)) {
			throw "Sobreposição com a área WindowsCleanup: $($rootEntry.Path)"
		}
	}

	New-Item -ItemType Directory -Path $runPath -Force -Confirm:$false -WhatIf:$false | Out-Null
	Start-Transcript -Path $logPath -NoClobber -IncludeInvocationHeader -Confirm:$false -WhatIf:$false | Out-Null
	$transcriptStarted = $true
	Write-Host "Execução: $runId"
	Write-Host "Computador: $env:COMPUTERNAME"
	Write-Host "Utilizador: $env:USERNAME"
	Write-Host "PowerShell: $($PSVersionTable.PSVersion)"
	Write-Host "Aplicar: $Apply"
	Write-Host "Permanente: $Permanent"
	Write-Host "Idade mínima: $OlderThanDays dias"
	if (-not $Apply -or $WhatIfPreference) {
		Write-Warning 'MODO SIMULAÇÃO: nenhum ficheiro temporário será movido ou eliminado. A pasta da execução, o log e o manifesto serão criados para auditoria.'
	}

	foreach ($rootEntry in $normalizedRoots) {
		if ($limitReached) { break }
		foreach ($file in Get-SafeFiles -Root $rootEntry.Path) {
			$destination = $null
			$hash = $null
			try {
				$currentFile = Get-Item -LiteralPath $file.FullName -Force -ErrorAction Stop
				if (($currentFile.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
					$filesReparseDetected++
					$manifest.Add([pscustomobject]@{
						OriginalPath = $currentFile.FullName; QuarantinePath = $null; Length = $currentFile.Length; Sha256 = $null; LastWriteTimeUtc = $currentFile.LastWriteTimeUtc; OperationUtc = (Get-Date).ToUniversalTime()
						Action = $manifestAction; Status = 'ReparsePointDetected'; Error = 'O objeto foi identificado como reparse point após a seleção.'
					})
					continue
				}
				if ($currentFile.LastWriteTimeUtc -ge $cutoffUtc -or $currentFile.Length -ne $file.Length) {
					$filesChangedBeforeProcessing++
					$manifest.Add([pscustomobject]@{
						OriginalPath = $currentFile.FullName; QuarantinePath = $null; Length = $currentFile.Length; Sha256 = $null; LastWriteTimeUtc = $currentFile.LastWriteTimeUtc; OperationUtc = (Get-Date).ToUniversalTime()
						Action = $manifestAction; Status = 'ChangedBeforeProcessing'; Error = 'O tamanho ou a data de alteração mudou após a seleção.'
					})
					Write-Warning "Ficheiro alterado entretanto, ignorado: $($file.FullName)"
					continue
				}
				$rootPrefix = $rootEntry.Path.TrimEnd('\') + '\'
				if (-not $currentFile.FullName.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
					throw "Ficheiro fora da raiz autorizada: $($currentFile.FullName)"
				}
				$relativePath = $currentFile.FullName.Substring($rootPrefix.Length)
				$destination = Join-Path (Join-Path $quarantinePath $rootEntry.Name) $relativePath
				$action = if ($Permanent) { 'Apagar permanentemente' } else { "Mover para '$destination'" }
				if (-not $Permanent) {
					$hash = (Get-FileHash -LiteralPath $currentFile.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
					$verifiedFile = Get-Item -LiteralPath $currentFile.FullName -Force -ErrorAction Stop
					if ($verifiedFile.Length -ne $currentFile.Length -or $verifiedFile.LastWriteTimeUtc -ne $currentFile.LastWriteTimeUtc) {
						throw 'O ficheiro foi alterado durante o cálculo do SHA-256.'
					}
				}

				if (-not $Apply) {
					$manifest.Add([pscustomobject]@{
						OriginalPath = $currentFile.FullName; QuarantinePath = if ($Permanent) { $null } else { $destination }
						Length = $currentFile.Length; Sha256 = $hash; LastWriteTimeUtc = $currentFile.LastWriteTimeUtc; OperationUtc = (Get-Date).ToUniversalTime()
						Action = if ($Permanent) { 'PermanentDelete' } else { 'Quarantine' }; Status = 'Simulated'; Error = $null
					})
					Write-Host "Simulação: $action`: $($currentFile.FullName)"
					continue
				}
				if (-not $PSCmdlet.ShouldProcess($currentFile.FullName, $action)) {
					$manifest.Add([pscustomobject]@{
						OriginalPath = $currentFile.FullName; QuarantinePath = if ($Permanent) { $null } else { $destination }
						Length = $currentFile.Length; Sha256 = $hash; LastWriteTimeUtc = $currentFile.LastWriteTimeUtc; OperationUtc = (Get-Date).ToUniversalTime()
						Action = $manifestAction; Status = 'NotProcessed'; Error = $null
					})
					continue
				}

				if ($Permanent) {
					Remove-Item -LiteralPath $currentFile.FullName -Force -Confirm:$false -ErrorAction Stop
				}
				else {
					$destinationDirectory = Split-Path -Parent $destination
					New-Item -ItemType Directory -Path $destinationDirectory -Force -Confirm:$false -ErrorAction Stop | Out-Null
					if (-not (Test-NoReparsePointInExistingParents -Path $destination -StopAtRoot $quarantinePath)) {
						throw 'Percurso de quarentena inseguro antes da movimentação.'
					}
					if (Test-Path -LiteralPath $destination) { throw "Destino já existente: $destination" }
					Move-Item -LiteralPath $currentFile.FullName -Destination $destination -Confirm:$false -ErrorAction Stop
					$destinationItem = Get-Item -LiteralPath $destination -Force -ErrorAction Stop
					if (($destinationItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
						throw 'O ficheiro na quarentena é um reparse point.'
					}
					if ($destinationItem.Length -ne $currentFile.Length) {
						throw 'O tamanho do ficheiro na quarentena não corresponde à origem.'
					}
					$destinationHash = (Get-FileHash -LiteralPath $destination -Algorithm SHA256 -ErrorAction Stop).Hash
					if ($destinationHash -ine $hash) {
						throw 'O SHA-256 do ficheiro na quarentena não corresponde à origem.'
					}
				}

				$filesProcessed++
				$bytesProcessed += $currentFile.Length
				$manifest.Add([pscustomobject]@{
					OriginalPath = $currentFile.FullName; QuarantinePath = if ($Permanent) { $null } else { $destination }
					Length = $currentFile.Length; Sha256 = $hash; LastWriteTimeUtc = $currentFile.LastWriteTimeUtc; OperationUtc = (Get-Date).ToUniversalTime()
					Action = $manifestAction; Status = 'Success'; Error = $null
				})
				Write-Host "$action`: $($currentFile.FullName)"
			}
			catch {
				$filesFailed++
				$originalException = $_.Exception
				$errorMessage = $_.Exception.Message
				$recoveryStatus = 'Failed'
				if (-not $Permanent -and $destination -and (Test-Path -LiteralPath $destination -PathType Leaf) -and -not (Test-Path -LiteralPath $file.FullName)) {
					try {
						$destinationItem = Get-Item -LiteralPath $destination -Force -ErrorAction Stop
						if (($destinationItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or [string]::IsNullOrWhiteSpace($hash) -or (Get-FileHash -LiteralPath $destination -Algorithm SHA256 -ErrorAction Stop).Hash -ine $hash) { throw 'Destino não passou a validação de rollback.' }
						$originalDirectory = Split-Path -Parent $file.FullName
						New-Item -ItemType Directory -Path $originalDirectory -Force -Confirm:$false -ErrorAction Stop | Out-Null
						if (-not $PSCmdlet.ShouldProcess($file.FullName, "Repor ficheiro após falha a partir de '$destination'")) { throw 'Rollback não autorizado por ShouldProcess.' }
						Move-Item -LiteralPath $destination -Destination $file.FullName -Confirm:$false -ErrorAction Stop
						$recoveryStatus = 'RolledBack'
					}
					catch {
						$recoveryStatus = 'QuarantinedAfterFailure'
						$errorMessage += " | Falha no rollback: $($_.Exception.Message)"
					}
				}
				if ($originalException -is [IO.IOException]) {
					$filesWithIoError++
				}
				$manifest.Add([pscustomobject]@{
					OriginalPath = $file.FullName; QuarantinePath = $destination; Length = $file.Length; Sha256 = $hash; LastWriteTimeUtc = $file.LastWriteTimeUtc; OperationUtc = (Get-Date).ToUniversalTime()
					Action = $manifestAction; Status = $recoveryStatus; Error = $errorMessage
				})
				Write-Warning ("Falha em '{0}': {1}" -f $file.FullName, $errorMessage)
			}
		}
	}

	Write-Host "`nFicheiros analisados: $filesChecked"
	Write-Host "Ficheiros excluídos: $filesExcluded"
	Write-Host "Ficheiros recentes: $filesTooRecent"
	Write-Host "Ficheiros selecionados: $filesSelected"
	Write-Host "Ficheiros processados: $filesProcessed"
	Write-Host "Alterados antes do processamento: $filesChangedBeforeProcessing"
	Write-Host "Reparse points detetados: $filesReparseDetected"
	Write-Host "Falhas de entrada/saída: $filesWithIoError"
	Write-Host "Diretórios não acessíveis: $directoriesFailed"
	Write-Host "Ignorados pelo limite de tamanho: $filesSkippedBySize"
	Write-Host "Ficheiros com erro: $filesFailed"
	Write-Host "Tamanho selecionado: $([math]::Round($bytesSelected / 1GB, 3)) GB"
	Write-Host "Tamanho processado: $([math]::Round($bytesProcessed / 1GB, 3)) GB"
	if ($limitReached) { Write-Warning 'A análise foi interrompida porque atingiu o limite máximo de ficheiros. Podem existir outros candidatos que não foram analisados.' }
	Write-Host "Log: $logPath"
	if (-not $Permanent -and $filesProcessed -gt 0) { Write-Host "Quarentena: $quarantinePath" }
	if ($manifest.Count -gt 0) { Write-Host "Manifesto previsto: $manifestPath" }
}
catch {
	$exitCode = 1
	Write-Error -Message "Falha crítica: $($_.Exception.Message)" -ErrorAction Continue
}
finally {
	if ($manifest.Count -gt 0) {
		try {
			$manifest | Export-Csv -LiteralPath $manifestPath -NoTypeInformation -Encoding UTF8 -NoClobber -Confirm:$false -WhatIf:$false
		}
		catch { Write-Warning "Não foi possível guardar o manifesto: $($_.Exception.Message)"; $exitCode = 1 }
	}
	else {
		try {
			'OriginalPath,QuarantinePath,Length,Sha256,LastWriteTimeUtc,OperationUtc,Action,Status,Error' |
				Set-Content -LiteralPath $manifestPath -Encoding UTF8 -NoNewline -Confirm:$false -WhatIf:$false
		}
		catch { Write-Warning "Não foi possível criar o manifesto vazio: $($_.Exception.Message)"; $exitCode = 1 }
	}
	if ($exitCode -eq 0 -and $filesFailed -eq 0 -and $directoriesFailed -eq 0 -and -not ($manifest | Where-Object { $_.Status -eq 'QuarantinedAfterFailure' })) {
		try {
			$manifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256 -ErrorAction Stop).Hash
			Set-Content -LiteralPath $manifestHashPath -Value $manifestHash -Encoding ASCII -NoNewline -Confirm:$false -WhatIf:$false
			$completion = [pscustomobject]@{
				SchemaVersion = 1; RunId = $runId; Mode = if (-not $Apply -or $WhatIfPreference) { 'Simulation' } elseif ($Permanent) { 'PermanentDelete' } else { 'Quarantine' }
				CompletedUtc = (Get-Date).ToUniversalTime().ToString('o', [Globalization.CultureInfo]::InvariantCulture); ExitCode = $exitCode; ManifestSha256 = $manifestHash
				FilesProcessed = $filesProcessed; BytesProcessed = $bytesProcessed; FilesFailed = $filesFailed; DirectoriesFailed = $directoriesFailed
			}
			$completion | ConvertTo-Json | Set-Content -LiteralPath $completedPath -Encoding UTF8 -NoNewline -Confirm:$false -WhatIf:$false
		}
		catch { Write-Warning "Não foi possível guardar a integridade da execução: $($_.Exception.Message)"; $exitCode = 1 }
	}
	if ($transcriptStarted) { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null }
	if ($mutexAcquired) { $mutex.ReleaseMutex() | Out-Null }
	$mutex.Dispose()
}

exit $exitCode
