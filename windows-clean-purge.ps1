#requires -Version 5.1
<##
.SYNOPSIS
Compatibility wrapper for windows-clean-expire.ps1.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [ValidateRange(7,365)][int]$RetentionDays = 14,
    [switch]$Apply
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'windows-clean-expire.ps1') -RetentionDays $RetentionDays -Apply:$Apply -WhatIf:$WhatIfPreference
exit $LASTEXITCODE
