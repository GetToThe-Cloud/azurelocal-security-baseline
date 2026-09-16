# Azure Local security baseline

Audit and remediate the security baseline of an Azure Local system, and deploy the Azure-side policy that proves it.

Companion code for the [gettothe.cloud](https://www.gettothe.cloud) series *Azure Local: Security Done Right*.

Azure Local ships with a strong default posture: several hundred enforced baseline settings, drift control that repairs tampering every ninety minutes, Application Control in enforcement mode, BitLocker, Credential Guard and HVCI. What it does not ship with is a way to answer, on a Tuesday morning eighteen months later, whether all of that is still true, and to prove it to an auditor. That is what this repository is for.

```powershell
Import-Module ./src/AzLocalSecurityBaseline

# Audit. Read-only, always safe.
Test-AzLocalSecurityBaseline -Scope Cluster |
    Where-Object Status -eq 'NonCompliant' |
    Format-Table Id, Severity, Title, Actual

# Report.
Test-AzLocalSecurityBaseline -Scope Cluster |
    New-AzLocalSecurityReport -Path C:\Reports\baseline.html

# Remediate. Opt-in, and it shows you the plan first.
Set-AzLocalSecurityBaseline -Scope Cluster -WhatIf
```

## What it checks

26 controls across eight categories, each one pinned to a Microsoft Learn reference and each one carrying the reason it matters, so a report reads as an argument rather than a list of settings.

| Category | Controls |
|---|---|
| Hardware root of trust | TPM 2.0 present and ready, UEFI Secure Boot enabled |
| Security baseline | Drift control enabled |
| Platform security features | VBS, HVCI, Credential Guard, DRTM, side channel mitigations |
| Data in transit | SMB signing, SMB cluster encryption |
| Application Control | Enforced mode, supplemental policies on an approved list |
| Data at rest | Boot volumes encrypted, CSVs encrypted, recovery keys retrievable |
| Malware protection | Real-time protection, signature currency, PUA blocking |
| Logging | Syslog forwarding configured, TLS transport, mutual authentication |
| Accounts and policy | RID 500 disabled, RID 501 disabled, 14-character passwords, logon banner |
| Lifecycle | Solution update environment healthy |

## Design decisions worth knowing about

**Read-only by default.** `Test-AzLocalSecurityBaseline` and `Get-AzLocalSecurityState` cannot write. Only `Set-AzLocalSecurityBaseline` changes anything, it supports `-WhatIf`, and its `ConfirmImpact` is High so it prompts unless you pass `-Confirm:$false`.

**Unknown is not a pass.** A control whose state could not be read, because a cmdlet is missing, a node is unreachable or CredSSP was refused, reports `Unknown`. Those are excluded from the compliance score rather than counted as compliant, and they are never remediated. If the module could not read the current state, it has no business writing a new one.

**Disruption is opt-in separately from remediation.** Anything that needs a reboot is skipped unless you pass `-AllowReboot`. Anything that pauses workloads, such as encrypting an existing CSV, is skipped unless you pass `-AllowMaintenanceWindow`. Neither flag is implied by the other, and the module never reboots a node itself.

**Some things are deliberately not automated.** Disabling the built-in RID 500 administrator is a finding, not a remediation, because doing it before a verified replacement account exists is how you lock yourself out of a cluster. Secure Boot and TPM are firmware, so the module reports on them and stops there.

**Key material never leaves the cluster.** The BitLocker control verifies that recovery keys are retrievable and records how many exist on which nodes. It never writes key material to a report, a log or the JSON sidecar. There is a test asserting exactly that.

## Installing

Requires Windows PowerShell 5.1 or PowerShell 7, running on an Azure Local node or a management session with the Azure Local cmdlets available.

```powershell
git clone https://github.com/GetToThe-Cloud/azure-local-security-baseline.git
Import-Module ./azure-local-security-baseline/src/AzLocalSecurityBaseline
```

Cluster-wide scopes (`-Scope Cluster` and `-Scope AllNodes`) need CredSSP or a direct RDP session to a node, which is a constraint of the underlying Azure Local cmdlets rather than of this module. `-Scope Local` works from a plain remote session.

## Configuring

Every control is on by default. To change something, write a file containing only what differs and pass it with `-ConfigPath`. Values are merged over the shipped default, so a site configuration is usually a few lines.

```json
{
  "profile": "Contoso-Production",
  "controls": {
    "AZL-WDAC-002": {
      "parameters": { "approvedPolicies": ["VeeamAgent", "ContosoMonitoring"] }
    },
    "AZL-SMB-002": { "enabled": false },
    "AZL-PWD-001": {
      "parameters": { "minimumLength": 16 }
    }
  }
}
```

Disabling a control is a decision, not a fix. The shipped default `baseline.default.json` is the reference for every available key.

## Reporting

`New-AzLocalSecurityReport` writes a self-contained HTML file with no external dependencies, so it renders years later on a machine with no internet access, and a JSON sidecar beside it for a SIEM or for diffing between runs.

```powershell
$summary = Test-AzLocalSecurityBaseline -Scope Cluster |
    New-AzLocalSecurityReport -Path .\baseline.html -PassThru

if ($summary.CriticalFindings -gt 0) { exit 1 }
```

## The Azure side

The `bicep/` folder deploys what the cluster cannot do for itself: the Microsoft Cloud Security Benchmark initiative that produces the regulatory compliance report, the Azure compute security baseline audit covering the Arc-enabled nodes and Windows workload VMs, and the Defender for Servers plan that adds behavioural threat detection on top of configuration checking.

```powershell
cd bicep
./Deploy-SecurityBaselinePolicy.ps1 -SubscriptionId <guid> -WhatIf
./Deploy-SecurityBaselinePolicy.ps1 -SubscriptionId <guid>
```

Built-in definitions are pinned by GUID rather than by display name, because display names change between releases and a renamed definition would silently break the deployment.

## Running it on a schedule

A weekly audit that lands in a share and shouts when something critical breaks:

```powershell
$stamp = Get-Date -Format 'yyyy-MM-dd'
$path = "\\fileserver\compliance\azurelocal\$stamp.html"

$summary = Test-AzLocalSecurityBaseline -Scope Cluster -ConfigPath C:\Config\site.json |
    New-AzLocalSecurityReport -Path $path -PassThru

if ($summary.CriticalFindings -gt 0 -or $summary.Unknown -gt 0) {
    Send-MailMessage -To 'platform-team@contoso.com' `
        -Subject "Azure Local baseline: $($summary.CriticalFindings) critical, $($summary.Unknown) unknown" `
        -Body "Report: $path"
}
```

Keep those reports. Collected continuously, an audit is a morning's work. Collected retrospectively, it is a month.

## Testing

```powershell
# No dependencies. Stubs the interop layer; touches nothing on the host.
pwsh -File ./tests/Invoke-SmokeTest.ps1

# The same coverage under Pester 5, for CI.
Invoke-Pester ./tests/AzLocalSecurityBaseline.Tests.ps1
```

Both suites mock every call into Azure Local, so they run anywhere. Among other things they assert that an audit never calls a write path, that a missing cmdlet produces `Unknown` rather than `Compliant`, that remediation refuses to touch a reboot-requiring control without `-AllowReboot`, and that recovery key material never reaches a result object.

## Extending it

Adding a control means adding one entry to `Private/Controls.ps1` and one to `Config/baseline.default.json`. A test asserts those two stay in step in both directions, so a control with no configuration entry, or a configuration entry with no control, fails the build.

Everything that talks to Azure Local goes through a wrapper in `Private/Interop.ps1`. Nothing else calls those cmdlets directly, which is what makes the whole thing testable on a laptop.

Control scriptblocks deliberately avoid `GetNewClosure()`. A closure binds to a snapshot of the scope that created it, which detaches it from the module's function table: the control then cannot see the interop layer, and the interop layer cannot be substituted for testing. Anything a control needs arrives through its `$Context` instead.

## References

- [Security features for Azure Local](https://learn.microsoft.com/en-us/azure/azure-local/concepts/security-features)
- [Manage security defaults on Azure Local](https://learn.microsoft.com/en-us/azure/azure-local/manage/manage-secure-baseline)
- [Manage Application Control on Azure Local](https://learn.microsoft.com/en-us/azure/azure-local/manage/manage-wdac)
- [Manage BitLocker encryption on Azure Local](https://learn.microsoft.com/en-us/azure/azure-local/manage/manage-bitlocker)
- [Manage syslog forwarding for security](https://learn.microsoft.com/en-us/azure/azure-local/manage/manage-syslog-forwarding)
- [ISO 27001 guidance for Azure Local](https://learn.microsoft.com/en-us/azure/azure-local/assurance/azure-stack-iso27001-guidance)

## License

MIT. See [LICENSE](LICENSE).
