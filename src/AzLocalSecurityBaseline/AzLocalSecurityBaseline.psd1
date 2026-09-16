@{
    RootModule            = 'AzLocalSecurityBaseline.psm1'
    ModuleVersion         = '1.0.0'
    GUID                  = 'b7f4c2e1-5a83-4d96-9c07-3e1f8a4b6d20'
    Author                = 'Alex ter Neuzen'
    CompanyName           = 'gettothe.cloud'
    Copyright             = '(c) Alex ter Neuzen. Licensed under the MIT License.'

    Description           = 'Audits and optionally remediates the security baseline of an Azure Local system. Read-only by default: covers the hardware root of trust, drift-protected platform features, Application Control, BitLocker, Defender, syslog forwarding, account policy and lifecycle currency, and produces a self-contained HTML report with a JSON sidecar.'

    PowerShellVersion     = '5.1'
    CompatiblePSEditions  = @('Desktop', 'Core')

    FunctionsToExport     = @(
        'Test-AzLocalSecurityBaseline'
        'Set-AzLocalSecurityBaseline'
        'Get-AzLocalSecurityState'
        'New-AzLocalSecurityReport'
    )
    CmdletsToExport       = @()
    VariablesToExport     = @()
    AliasesToExport       = @()

    FileList              = @(
        'AzLocalSecurityBaseline.psd1'
        'AzLocalSecurityBaseline.psm1'
        'Config/baseline.default.json'
        'Private/Controls.ps1'
        'Private/Helpers.ps1'
        'Private/Interop.ps1'
        'Public/Get-AzLocalSecurityState.ps1'
        'Public/New-AzLocalSecurityReport.ps1'
        'Public/Set-AzLocalSecurityBaseline.ps1'
        'Public/Test-AzLocalSecurityBaseline.ps1'
    )

    PrivateData = @{
        PSData = @{
            Tags         = @('AzureLocal', 'AzureStackHCI', 'Security', 'Baseline', 'Compliance', 'Hardening', 'CIS', 'STIG', 'Windows')
            LicenseUri   = 'https://github.com/GetToThe-Cloud/azure-local-security-baseline/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/GetToThe-Cloud/azure-local-security-baseline'
            ReleaseNotes = @'
1.0.0
  - Initial release.
  - 26 controls across hardware root of trust, platform security features,
    Application Control, data at rest, malware protection, logging, accounts
    and lifecycle.
  - Audit-only by default; remediation is opt-in and gated behind -AllowReboot
    and -AllowMaintenanceWindow.
  - HTML report with JSON sidecar.
  - Companion Bicep for the Microsoft Cloud Security Benchmark assignment,
    guest configuration on Arc-enabled nodes and the Defender for Servers plan.
'@
        }
    }
}
