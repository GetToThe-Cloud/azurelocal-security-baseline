#requires -Version 5.1
<#
    AzLocalSecurityBaseline

    Audit and remediate the security baseline of an Azure Local system.

    Read-only by default. Set-AzLocalSecurityBaseline is the only function that
    changes anything, it supports -WhatIf, and it refuses to perform any
    remediation that reboots a node or pauses workloads unless explicitly told to.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ModuleRoot = $PSScriptRoot
$script:ControlRegistryCache = $null

$manifestPath = Join-Path -Path $PSScriptRoot -ChildPath 'AzLocalSecurityBaseline.psd1'
$script:ModuleVersion = if (Test-Path -LiteralPath $manifestPath) {
    (Import-PowerShellDataFile -Path $manifestPath).ModuleVersion
} else {
    '0.0.0'
}

# Private first: the public functions depend on them at load time.
foreach ($folder in @('Private', 'Public')) {
    $path = Join-Path -Path $PSScriptRoot -ChildPath $folder
    if (-not (Test-Path -LiteralPath $path)) { continue }

    foreach ($file in (Get-ChildItem -Path $path -Filter '*.ps1' -File | Sort-Object Name)) {
        try {
            . $file.FullName
        }
        catch {
            throw "Failed to load '$($file.FullName)': $($_.Exception.Message)"
        }
    }
}

Export-ModuleMember -Function @(
    'Test-AzLocalSecurityBaseline'
    'Set-AzLocalSecurityBaseline'
    'Get-AzLocalSecurityState'
    'New-AzLocalSecurityReport'
)
