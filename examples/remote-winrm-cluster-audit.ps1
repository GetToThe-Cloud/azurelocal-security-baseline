# Cluster-wide scopes need CredSSP or an existing delegated PSSession.

Import-Module (Join-Path $PSScriptRoot '../src/AzLocalSecurityBaseline')

$computerName = 'azl-node01.contoso.local'
$target = New-AzLocalSecurityRemoteTarget -Transport WinRM `
    -ComputerName $computerName `
    -Authentication CredSSP `
    -Credential (Get-Credential)

Test-AzLocalSecurityBaseline -Target $target -Scope AllNodes |
    New-AzLocalSecurityReport -Path 'C:\Reports\azurelocal-all-nodes.html'
