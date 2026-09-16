#requires -Version 7.0
<#
    .SYNOPSIS
        Deploys the Azure-side half of the Azure Local security baseline.

    .DESCRIPTION
        Wraps 'az deployment sub' with the two things people forget: a what-if
        pass before the real deployment, and a remediation task afterwards so
        existing machines are evaluated rather than only new ones.

        Run the what-if first. Policy assignments are cheap to create and
        annoying to clean up.

    .PARAMETER SubscriptionId
        Target subscription. The signed-in account needs Resource Policy
        Contributor on it, and User Access Administrator as well if guest
        configuration prerequisites are being deployed, because that assignment
        creates a role assignment.

    .PARAMETER ParameterFile
        Path to a .bicepparam file. Defaults to main.bicepparam beside this script.

    .PARAMETER WhatIf
        Show what would change and deploy nothing.

    .PARAMETER SkipRemediation
        Do not create remediation tasks after deploying.

    .EXAMPLE
        ./Deploy-SecurityBaselinePolicy.ps1 -SubscriptionId <guid> -WhatIf

    .EXAMPLE
        ./Deploy-SecurityBaselinePolicy.ps1 -SubscriptionId <guid> -ParameterFile ./sittard.bicepparam
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string] $SubscriptionId,

    [string] $ParameterFile = (Join-Path $PSScriptRoot 'main.bicepparam'),

    [string] $Location = 'westeurope',

    [string] $DeploymentName = "azlocal-security-baseline-$(Get-Date -Format 'yyyyMMdd-HHmmss')",

    [switch] $SkipRemediation
)

$ErrorActionPreference = 'Stop'

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    throw 'The Azure CLI is required. Install it from https://learn.microsoft.com/cli/azure/install-azure-cli'
}

if (-not (Test-Path -LiteralPath $ParameterFile)) {
    throw "Parameter file not found: $ParameterFile"
}

$templateFile = Join-Path $PSScriptRoot 'main.bicep'

Write-Host "Subscription : $SubscriptionId"
Write-Host "Template     : $templateFile"
Write-Host "Parameters   : $ParameterFile"
Write-Host ''

az account set --subscription $SubscriptionId | Out-Null

# Always show the diff, whether or not this run will apply it.
Write-Host 'Running what-if...' -ForegroundColor Cyan
az deployment sub what-if `
    --name $DeploymentName `
    --location $Location `
    --template-file $templateFile `
    --parameters $ParameterFile

if ($WhatIfPreference) {
    Write-Host ''
    Write-Host 'What-if only. Nothing was deployed.' -ForegroundColor Yellow
    return
}

if (-not $PSCmdlet.ShouldProcess($SubscriptionId, 'Deploy Azure Local security baseline policy')) {
    return
}

Write-Host ''
Write-Host 'Deploying...' -ForegroundColor Cyan

$output = az deployment sub create `
    --name $DeploymentName `
    --location $Location `
    --template-file $templateFile `
    --parameters $ParameterFile `
    --output json | ConvertFrom-Json

if ($LASTEXITCODE -ne 0) {
    throw "Deployment failed with exit code $LASTEXITCODE."
}

Write-Host 'Deployed.' -ForegroundColor Green
$output.properties.outputs.PSObject.Properties |
    ForEach-Object { Write-Host ("  {0}: {1}" -f $_.Name, $_.Value.value) }

if ($SkipRemediation) {
    Write-Host ''
    Write-Host 'Skipped the compliance scan. Results will appear on the platform''s own schedule, within 24 hours.'
    return
}

# A new assignment evaluates on its own schedule, which can take up to 24 hours.
# Triggering a scan makes the compliance report useful today rather than
# tomorrow, which matters when the reason for deploying was an audit deadline.
Write-Host ''
Write-Host 'Triggering a compliance scan across the subscription. This can take several minutes...' -ForegroundColor Cyan

az policy state trigger-scan --no-wait

if ($LASTEXITCODE -ne 0) {
    Write-Warning 'Could not trigger the compliance scan. Results will still appear on the platform''s own schedule, within 24 hours.'
}

Write-Host ''
Write-Host 'Done. Compliance results appear in Defender for Cloud and under Policy > Compliance.' -ForegroundColor Green
Write-Host ''
Write-Host 'Note: deployIfNotExists assignments, such as the guest configuration prerequisites,' -ForegroundColor Yellow
Write-Host 'only act on new resources until you create a remediation task for the existing ones:' -ForegroundColor Yellow
Write-Host '  az policy remediation create --name remediate-gc-prereq --policy-assignment <assignmentId>' -ForegroundColor Yellow
