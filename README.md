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

The module is remote-first. Install it on a management computer and choose a
target for each run; the Azure Local cmdlets still execute on the node, but an
operator does not need to open an interactive session on that node.

```powershell
$target = New-AzLocalSecurityRemoteTarget -Transport WinRM `
    -ComputerName azl-node01 -Credential (Get-Credential)

$results = Test-AzLocalSecurityBaseline -Target $target -Scope Local
$results | New-AzLocalSecurityReport -Path C:\Reports\azurelocal.html
```

For cluster-wide values, create a delegated target explicitly:

```powershell
$target = New-AzLocalSecurityRemoteTarget -Transport WinRM `
    -ComputerName azl-node01 -Authentication CredSSP `
    -Credential (Get-Credential)

Test-AzLocalSecurityBaseline -Target $target -Scope AllNodes
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

Requires Windows PowerShell 5.1 or PowerShell 7 on the management computer. The
Azure Local cmdlets must be available on the execution node; they do not need to
be installed on the management computer when a remote target is used.

```powershell
git clone https://github.com/GetToThe-Cloud/azure-local-security-baseline.git
Import-Module ./azure-local-security-baseline/src/AzLocalSecurityBaseline
```

### Remote scope matrix

| Transport | Local | Cluster | AllNodes | Remediation |
|---|---:|---:|---:|---:|
| Local module run | Yes | Yes | Yes | Yes |
| WinRM/PSSession | Yes | Yes, with CredSSP/delegation | Yes, with CredSSP/delegation | Local/Cluster, with existing safety gates |
| Azure Arc Run Command | Yes | No | No | Local only |

`Cluster` and `AllNodes` are restrictions of the Azure Local cmdlets. A normal
remote PowerShell session is sufficient for `Local`; cluster-wide operations
need CredSSP or an already delegated PSSession. Arc Run Command intentionally
rejects those scopes instead of reporting a partial result as a successful
cluster audit.

Azure Arc Run Command is a preview feature. The Connected Machine agent must
support Run Command, the caller needs permission to write
`Microsoft.HybridCompute/machines/runCommands`, and the node needs outbound
connectivity to Azure. Use a unique `OutputBlobUri` for full structured output;
the command status stream is limited and can truncate large reports.
SAS values are held as secure strings in the target and are not included in the
remote request, result objects or reports. Recovery key material is summarized
only and is never sent through the remote executor.

```powershell
$target = New-AzLocalSecurityRemoteTarget -Transport ArcRunCommand `
    -SubscriptionId <subscription-id> `
    -ResourceGroupName rg-azurelocal `
    -MachineName azl-node01 `
    -Location westeurope `
    -OutputBlobUri $outputSasUri `
    -ErrorBlobUri $errorSasUri

Test-AzLocalSecurityBaseline -Target $target -Scope Local |
    New-AzLocalSecurityReport -Path C:\Reports\azl-node01.html
```

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

`New-AzLocalSecurityReport` writes a self-contained HTML file with no external dependencies, so it renders years later on a machine with no internet access, and a JSON sidecar beside it for a SIEM or for diffing between runs. Remote results include the transport, target, execution id and evaluation status. A run containing only `Unknown` results is marked `Incomplete`, never compliant.

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

## Running it centrally on a schedule

A weekly audit can run from a management server, jump box or automation worker.
Keep the configuration and reports outside the Azure Local node, use a service
identity or protected credential store, and alert on `Unknown` as well as on
findings:

```powershell
$stamp = Get-Date -Format 'yyyy-MM-dd'
$path = "\\fileserver\compliance\azurelocal\$stamp.html"

$target = New-AzLocalSecurityRemoteTarget -Transport WinRM `
    -ComputerName azl-node01 -Authentication CredSSP `
    -Credential (Get-Credential)

$summary = Test-AzLocalSecurityBaseline -Target $target -Scope Cluster -ConfigPath C:\Config\site.json |
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
