# Arc Run Command is node-local. Supply unique short-lived append-blob SAS URIs
# when the full structured result must be retrieved from Azure.

Import-Module (Join-Path $PSScriptRoot '../src/AzLocalSecurityBaseline')
Import-Module Az.Accounts
Connect-AzAccount
Set-AzContext -Subscription '<subscription-id>'

$target = New-AzLocalSecurityRemoteTarget -Transport ArcRunCommand `
    -SubscriptionId '<subscription-id>' `
    -ResourceGroupName 'rg-azurelocal' `
    -MachineName 'azl-node01' `
    -Location 'westeurope' `
    -OutputBlobUri $env:AZLOCAL_OUTPUT_BLOB_SAS `
    -ErrorBlobUri $env:AZLOCAL_ERROR_BLOB_SAS

Test-AzLocalSecurityBaseline -Target $target -Scope Local |
    New-AzLocalSecurityReport -Path 'C:\Reports\azurelocal-node01-arc.html'
