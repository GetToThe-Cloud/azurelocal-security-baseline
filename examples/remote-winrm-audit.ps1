# Run from a management computer. Store the credential in a protected scheduler
# or credential vault for unattended use; do not put a password in this file.

Import-Module (Join-Path $PSScriptRoot '../src/AzLocalSecurityBaseline')

$computerName = 'azl-node01.contoso.local'
$target = New-AzLocalSecurityRemoteTarget -Transport WinRM `
    -ComputerName $computerName `
    -Credential (Get-Credential)

$report = Join-Path $PSScriptRoot '../../reports/azurelocal-node01.html'
Test-AzLocalSecurityBaseline -Target $target -Scope Local `
    -ConfigPath (Join-Path $PSScriptRoot '../src/AzLocalSecurityBaseline/Config/site.json') |
    New-AzLocalSecurityReport -Path $report -PassThru
