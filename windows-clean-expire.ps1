#requires -Version 5.1
<##
.SYNOPSIS
Simulates or expires complete WindowsCleanup runs beyond the retention period.
.DESCRIPTION
Only validated run directories below the local WindowsCleanup Runs folder are eligible for expiration.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [ValidateRange(7,365)][int]$RetentionDays = 14,
    [switch]$Apply
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'WindowsCleanup.Common.psm1') -Force
$exitCode = 0
$lock = $null
$basePath = ConvertTo-NormalizedPath (Join-Path $env:LOCALAPPDATA 'WindowsCleanup')
$runsPath = Join-Path $basePath 'Runs'
$cutoffUtc = (Get-Date).ToUniversalTime().AddDays(-$RetentionDays)
$pattern = '^\d{8}-\d{9}-[0-9a-fA-F]{8}$'
$counters = [ordered]@{ Analysed=0; Recent=0; Invalid=0; Simulated=0; Deleted=0; Ignored=0; NotProcessed=0; Failed=0; ReparsePoints=0 }
try {
    $lock = Enter-WindowsCleanupMutex
    if (Test-Path -LiteralPath $runsPath -PathType Container) {
        foreach ($run in Get-ChildItem -LiteralPath $runsPath -Directory -Force -ErrorAction Stop) {
            $counters.Analysed++
            if (($run.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { $counters.ReparsePoints++; $counters.Invalid++; continue }
            if ($run.Name -notmatch $pattern) { $counters.Invalid++; continue }
            $stamp=$run.Name.Substring(0,18); $runDate=[DateTime]::MinValue
            if (-not [DateTime]::TryParseExact($stamp,'yyyyMMdd-HHmmssfff',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::AssumeUniversal,[ref]$runDate)) { $counters.Invalid++; continue }
            $runDate=[DateTime]::SpecifyKind($runDate,[DateTimeKind]::Utc)
            try {
                $path=ConvertTo-NormalizedPath $run.FullName
                if (-not (Test-DescendantPath $path $runsPath)) { throw 'Execução fora da raiz Runs.' }
                if ($runDate -ge $cutoffUtc) { $counters.Recent++; continue }
                $manifest=Join-Path $path 'manifest.csv'; $hashFile=Join-Path $path 'manifest.csv.sha256'; $completed=Join-Path $path 'completed.json'
                foreach ($required in @($manifest,$hashFile,$completed)) { if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { throw "Artefacto em falta: $required" }; $item=Get-Item -LiteralPath $required -Force -ErrorAction Stop; if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Reparse point: $required" } }
                $expected=(Get-Content -LiteralPath $hashFile -Raw).Trim().ToUpperInvariant(); $actual=(Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash.ToUpperInvariant(); if ($expected -notmatch '^[0-9A-F]{64}$' -or $expected -cne $actual) { throw 'Hash do manifesto inválido ou divergente.' }
                $completion=Get-Content -LiteralPath $completed -Raw | ConvertFrom-Json; if ($completion.RunId -cne $run.Name -or [int]$completion.ExitCode -ne 0 -or [string]$completion.ManifestSha256 -ine $actual) { throw 'Marcador de conclusão inválido.' }
                $unsafe=Get-ChildItem -LiteralPath $path -Force -Recurse -ErrorAction Stop | Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 } | Select-Object -First 1; if ($unsafe) { $counters.ReparsePoints++; throw "Reparse point encontrado: $($unsafe.FullName)" }
                $action='Eliminar execução completa (quarentena, manifesto, logs e restantes artefactos)'
                if (-not $Apply) { $counters.Simulated++; Write-Host "Simulação: $action -> $path"; continue }
                if (-not $PSCmdlet.ShouldProcess($path,$action)) { $counters.NotProcessed++; continue }
                Remove-Item -LiteralPath $path -Recurse -Force -Confirm:$false -ErrorAction Stop; if (Test-Path -LiteralPath $path) { throw 'A execução ainda existe após a remoção.' }; $counters.Deleted++
            } catch { $counters.Failed++; Write-Warning "Falha ao processar '$($run.FullName)': $($_.Exception.Message)" }
        }
    }
} catch { $exitCode=1; Write-Error -Message $_.Exception.Message -ErrorAction Continue }
finally { if ($null -ne $lock) { Exit-WindowsCleanupMutex $lock } }
Write-Host "Execuções analisadas: $($counters.Analysed)"; Write-Host "Recentes: $($counters.Recent)"; Write-Host "Simuladas: $($counters.Simulated)"; Write-Host "Eliminadas: $($counters.Deleted)"; Write-Host "Ignoradas: $($counters.Ignored)"; Write-Host "Não processadas: $($counters.NotProcessed)"; Write-Host "Falhadas: $($counters.Failed)"; Write-Host "Reparse points: $($counters.ReparsePoints)"
if ($counters.Failed -gt 0) { $exitCode=1 }
exit $exitCode
