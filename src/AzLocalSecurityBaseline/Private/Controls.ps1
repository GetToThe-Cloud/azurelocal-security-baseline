#requires -Version 5.1
<#
    Controls.ps1

    The control registry. Every check the module performs is defined here as a
    single object with a Test scriptblock and, where safe automation exists, a
    Remediate scriptblock.

    Adding a control means adding one entry here. Nothing else changes.

    Control object contract
    -----------------------
      Id                        Stable identifier, used in config files and reports
      Title                     One line, states the desired condition
      Category                  Groups controls in the report
      Severity                  Critical | High | Medium | Low
      Rationale                 Why this matters, in plain language
      Reference                 Microsoft Learn URL backing the control
      RequiresReboot            Remediation reboots the node
      RequiresMaintenanceWindow Remediation pauses workloads
      Remediable                A Remediate scriptblock exists
      Test                      param($Context) -> New-AzLocalCheckResult
      Remediate                 param($Context) -> probe result, or $null
      Data                      Static values the scriptblocks need, such as the
                                Get-AzsSecurity feature name

    $Context is a hashtable carrying:
      Config      the merged desired-state configuration
      Scope       Local | Cluster | AllNodes
      Parameters  this control's parameters block from the configuration
      Data        the control's own Data bag

    Control scriptblocks deliberately do NOT use GetNewClosure(). A closure is
    bound to a snapshot of the scope that created it, which detaches it from the
    module's function table: the control then cannot see the interop layer, and
    the interop layer cannot be substituted for testing. Everything a scriptblock
    needs arrives through $Context instead.
#>

function New-AzLocalControl {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $Id,
        [Parameter(Mandatory)] [string] $Title,
        [Parameter(Mandatory)] [string] $Category,
        [Parameter(Mandatory)] [ValidateSet('Critical', 'High', 'Medium', 'Low')] [string] $Severity,
        [Parameter(Mandatory)] [string] $Rationale,
        [Parameter(Mandatory)] [string] $Reference,
        [Parameter(Mandatory)] [scriptblock] $Test,
        [scriptblock] $Remediate,
        [hashtable] $Data = @{},
        [switch] $RequiresReboot,
        [switch] $RequiresMaintenanceWindow
    )

    return [pscustomobject]@{
        PSTypeName                = 'AzLocal.Control'
        Id                        = $Id
        Title                     = $Title
        Category                  = $Category
        Severity                  = $Severity
        Rationale                 = $Rationale
        Reference                 = $Reference
        RequiresReboot            = [bool] $RequiresReboot
        RequiresMaintenanceWindow = [bool] $RequiresMaintenanceWindow
        Remediable                = [bool] $Remediate
        Data                      = $Data
        Test                      = $Test
        Remediate                 = $Remediate
    }
}

function New-AzLocalSecurityFeatureControl {
    <#
        .SYNOPSIS
            Builds a control for one drift-protected Get-AzsSecurity feature.

        .DESCRIPTION
            The eight features managed by Get/Enable/Disable-AzsSecurity share
            identical test and remediation shapes, so they are generated rather
            than copied. Only the metadata differs.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $Id,
        [Parameter(Mandatory)] [string] $FeatureName,
        [Parameter(Mandatory)] [string] $Title,
        [Parameter(Mandatory)] [string] $Severity,
        [Parameter(Mandatory)] [string] $Rationale,
        [Parameter(Mandatory)] [string] $Reference,
        [string] $Category = 'Platform security features',
        [switch] $RequiresReboot
    )

    $test = {
        param($Context)

        $feature = $Context.Data.FeatureName

        $desired = $true
        if ($Context.Parameters.ContainsKey('desired')) {
            $desired = [bool] $Context.Parameters['desired']
        }

        $probe = Get-AzLocalSecurityFeature -FeatureName $feature -Scope $Context.Scope

        if (-not $probe.Ok) {
            return New-AzLocalCheckResult -Status Unknown -Expected $desired `
                -Detail $probe.Message
        }

        $actual = Resolve-AzLocalFeatureValue -Value $probe.Value

        if ($null -eq $actual) {
            return New-AzLocalCheckResult -Status Unknown -Expected $desired `
                -Detail "Get-AzsSecurity returned a value for $feature that could not be interpreted as a boolean."
        }

        $status = if ($actual -eq $desired) { 'Compliant' } else { 'NonCompliant' }

        return New-AzLocalCheckResult -Status $status -Expected $desired -Actual $actual `
            -Detail "$feature is $(ConvertTo-AzLocalDisplayValue -Value $actual) at scope '$($Context.Scope)'." `
            -Evidence @{ FeatureName = $feature; Scope = $Context.Scope }
    }

    $remediate = {
        param($Context)

        $feature = $Context.Data.FeatureName

        $desired = $true
        if ($Context.Parameters.ContainsKey('desired')) {
            $desired = [bool] $Context.Parameters['desired']
        }

        # Enable-/Disable-AzsSecurity only accept -Local or -Cluster.
        $writeScope = if ($Context.Scope -eq 'Local') { 'Local' } else { 'Cluster' }

        return Set-AzLocalSecurityFeature -FeatureName $feature -Enabled $desired -Scope $writeScope
    }

    return New-AzLocalControl -Id $Id -Title $Title -Category $Category -Severity $Severity `
        -Rationale $Rationale -Reference $Reference -Test $test -Remediate $remediate `
        -Data @{ FeatureName = $FeatureName } -RequiresReboot:$RequiresReboot
}

function Resolve-AzLocalFeatureValue {
    <#
        .SYNOPSIS
            Normalises what Get-AzsSecurity returns into a boolean.

        .DESCRIPTION
            The cmdlet returns a bare boolean at -Local scope and an object
            carrying a per-node or computed value at the other scopes. Rather than
            guess, this looks for the common property names and falls back to
            $null, which the caller reports as Unknown.
    #>
    [CmdletBinding()]
    param($Value)

    if ($null -eq $Value) { return $null }
    if ($Value -is [bool]) { return $Value }

    # A collection of per-node results is compliant only if every node is.
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        $resolved = @()
        foreach ($item in $Value) {
            $itemValue = Resolve-AzLocalFeatureValue -Value $item
            if ($null -eq $itemValue) { return $null }
            $resolved += $itemValue
        }
        if ($resolved.Count -eq 0) { return $null }
        return (-not ($resolved -contains $false))
    }

    foreach ($name in @('Value', 'Enabled', 'State', 'Status', 'IsEnabled')) {
        $property = $Value.PSObject.Properties[$name]
        if ($property) {
            $inner = $property.Value
            if ($inner -is [bool]) { return $inner }
            if ($inner -is [string]) {
                switch -Regex ($inner) {
                    '^(?i)(true|enabled|on|yes)$'  { return $true }
                    '^(?i)(false|disabled|off|no)$' { return $false }
                }
            }
        }
    }

    return $null
}

function Get-AzLocalControlRegistry {
    <#
        .SYNOPSIS
            Returns every control the module knows about.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    if ($script:ControlRegistryCache) { return $script:ControlRegistryCache }

    $controls = New-Object System.Collections.Generic.List[object]

    #region Hardware root of trust

    $controls.Add((New-AzLocalControl -Id 'AZL-HW-001' -Category 'Hardware root of trust' -Severity 'Critical' `
        -Title 'A TPM 2.0 is present, enabled and owned' `
        -Rationale 'BitLocker binds its volume key to a measured boot state held in the TPM. Without a usable TPM 2.0 the boot volume cannot be protected and every measurement-based control above it is decoration.' `
        -Reference 'https://learn.microsoft.com/en-us/azure/azure-local/concepts/security-features' `
        -Test {
            param($Context)

            $probe = Get-AzLocalTpm
            if (-not $probe.Ok) {
                return New-AzLocalCheckResult -Status Unknown -Expected 'TPM present, ready' -Detail $probe.Message
            }

            $tpm = $probe.Value
            $present = [bool] $tpm.TpmPresent
            $ready = [bool] $tpm.TpmReady

            $status = if ($present -and $ready) { 'Compliant' } else { 'NonCompliant' }

            return New-AzLocalCheckResult -Status $status -Expected 'TPM present, ready' `
                -Actual "present=$present, ready=$ready" `
                -Detail 'A TPM that is present but not ready usually means it needs to be cleared and re-owned in firmware.' `
                -Evidence @{ TpmPresent = $present; TpmReady = $ready }
        }))

    $controls.Add((New-AzLocalControl -Id 'AZL-HW-002' -Category 'Hardware root of trust' -Severity 'Critical' `
        -Title 'UEFI Secure Boot is enabled' `
        -Rationale 'Secure Boot stops a modified bootloader from running underneath the operating system. It is a prerequisite for the measured launch the rest of the trust stack depends on, and it cannot be retrofitted without a rebuild.' `
        -Reference 'https://learn.microsoft.com/en-us/azure/azure-local/concepts/security-features' `
        -Test {
            param($Context)

            $probe = Get-AzLocalSecureBootState
            if (-not $probe.Ok) {
                # Confirm-SecureBootUEFI throws on a BIOS (non-UEFI) system rather
                # than returning false, which is itself a finding.
                return New-AzLocalCheckResult -Status Unknown -Expected $true -Detail $probe.Message
            }

            $actual = [bool] $probe.Value
            $status = if ($actual) { 'Compliant' } else { 'NonCompliant' }

            return New-AzLocalCheckResult -Status $status -Expected $true -Actual $actual `
                -Detail 'Secure Boot is configured in firmware and cannot be enabled from PowerShell.'
        }))

    #endregion

    #region Platform security features

    $controls.Add((New-AzLocalSecurityFeatureControl -Id 'AZL-DRIFT-001' -FeatureName 'DriftControl' `
        -Title 'Security baseline drift control is enabled' -Severity 'Critical' `
        -Category 'Security baseline' `
        -Rationale 'Drift control re-evaluates the protected baseline settings every 90 minutes and reverts anything that changed. Without it the baseline is a one-time hardening pass that decays, and a loosened setting stays loosened.' `
        -Reference 'https://learn.microsoft.com/en-us/azure/azure-local/manage/manage-secure-baseline'))

    $controls.Add((New-AzLocalSecurityFeatureControl -Id 'AZL-VBS-001' -FeatureName 'VBS' `
        -Title 'Virtualization-Based Security is enabled' -Severity 'Critical' -RequiresReboot `
        -Rationale 'VBS is the hypervisor-enforced memory boundary that Credential Guard and HVCI are built on. Neither of those controls means anything without it.' `
        -Reference 'https://learn.microsoft.com/en-us/azure/azure-local/manage/manage-secure-baseline'))

    $controls.Add((New-AzLocalSecurityFeatureControl -Id 'AZL-HVCI-001' -FeatureName 'HVCI' `
        -Title 'Hypervisor-protected code integrity is enabled' -Severity 'High' -RequiresReboot `
        -Rationale 'HVCI verifies that every kernel-mode driver is signed and unmodified before it runs, which closes an entire category of rootkit.' `
        -Reference 'https://learn.microsoft.com/en-us/azure/azure-local/manage/manage-secure-baseline'))

    $controls.Add((New-AzLocalSecurityFeatureControl -Id 'AZL-CG-001' -FeatureName 'CredentialGuard' `
        -Title 'Credential Guard is enabled' -Severity 'High' -RequiresReboot `
        -Rationale 'Credential Guard isolates derived credentials so that compromising a host does not hand an attacker reusable hashes to pivot with. It is the control that keeps one compromised node from becoming a domain compromise.' `
        -Reference 'https://learn.microsoft.com/en-us/azure/azure-local/manage/manage-secure-baseline'))

    $controls.Add((New-AzLocalSecurityFeatureControl -Id 'AZL-DRTM-001' -FeatureName 'DRTM' `
        -Title 'Dynamic Root of Trust for Measurement is enabled' -Severity 'High' -RequiresReboot `
        -Rationale 'DRTM establishes a clean measured launch environment after boot, so a firmware-level compromise no longer poisons everything downstream. Instances deployed before the 2504 release may still be on the older static root of trust.' `
        -Reference 'https://learn.microsoft.com/en-us/azure/azure-local/manage/manage-secure-baseline'))

    $controls.Add((New-AzLocalSecurityFeatureControl -Id 'AZL-SCM-001' -FeatureName 'SideChannelMitigation' `
        -Title 'Side channel mitigations are enabled' -Severity 'Medium' -RequiresReboot `
        -Rationale 'Speculative execution mitigations matter more on a hypervisor than anywhere else, because the boundary being attacked is the one between tenant workloads.' `
        -Reference 'https://learn.microsoft.com/en-us/azure/azure-local/manage/manage-secure-baseline'))

    $controls.Add((New-AzLocalSecurityFeatureControl -Id 'AZL-SMB-001' -FeatureName 'SMBSigning' `
        -Title 'SMB signing is enabled for external traffic' -Severity 'High' `
        -Category 'Data in transit' `
        -Rationale 'SMB signing prevents tampering and relay attacks on traffic leaving the cluster. Changing it does not need a reboot, though existing sessions keep the previous setting until they reconnect.' `
        -Reference 'https://learn.microsoft.com/en-us/azure/azure-local/manage/manage-secure-baseline'))

    $controls.Add((New-AzLocalSecurityFeatureControl -Id 'AZL-SMB-002' -FeatureName 'SMBClusterEncryption' `
        -Title 'SMB encryption is enabled for in-cluster traffic' -Severity 'Medium' `
        -Category 'Data in transit' `
        -Rationale 'East-west storage traffic between nodes carries workload data in clear text unless cluster encryption is on. Measure the throughput cost before enabling it on a latency-sensitive cluster, but measure it rather than assuming it.' `
        -Reference 'https://learn.microsoft.com/en-us/azure/azure-local/manage/manage-secure-baseline'))

    #endregion

    #region Application Control

    $controls.Add((New-AzLocalControl -Id 'AZL-WDAC-001' -Category 'Application Control' -Severity 'Critical' `
        -Title 'Application Control is in Enforced mode' `
        -Rationale 'Audit mode logs what would have been blocked and then allows it to run anyway. A cluster left in audit mode has the paperwork of application control with none of the protection, which is the single most common finding on a mature deployment.' `
        -Reference 'https://learn.microsoft.com/en-us/azure/azure-local/manage/manage-wdac' `
        -Test {
            param($Context)

            $desired = 'Enforced'
            if ($Context.Parameters.ContainsKey('desiredMode')) {
                $desired = [string] $Context.Parameters['desiredMode']
            }

            $probe = Get-AzLocalWdacMode
            if (-not $probe.Ok) {
                return New-AzLocalCheckResult -Status Unknown -Expected $desired -Detail $probe.Message
            }

            $modes = @()
            foreach ($item in @($probe.Value)) {
                if ($null -eq $item) { continue }
                if ($item -is [string]) { $modes += $item; continue }

                $property = $item.PSObject.Properties['Mode']
                if (-not $property) { $property = $item.PSObject.Properties['PolicyMode'] }
                if ($property) { $modes += [string] $property.Value } else { $modes += [string] $item }
            }

            if ($modes.Count -eq 0) {
                return New-AzLocalCheckResult -Status Unknown -Expected $desired `
                    -Detail 'Get-AsWdacPolicyMode returned no mode value.'
            }

            $offenders = @($modes | Where-Object { $_ -ne $desired })
            $status = if ($offenders.Count -eq 0) { 'Compliant' } else { 'NonCompliant' }

            return New-AzLocalCheckResult -Status $status -Expected $desired -Actual ($modes -join ', ') `
                -Detail "$($modes.Count) node result(s) read; $($offenders.Count) not in '$desired' mode." `
                -Evidence @{ Modes = $modes }
        } `
        -Remediate {
            param($Context)

            $desired = 'Enforced'
            if ($Context.Parameters.ContainsKey('desiredMode')) {
                $desired = [string] $Context.Parameters['desiredMode']
            }

            return Set-AzLocalWdacMode -Mode $desired
        }))

    $controls.Add((New-AzLocalControl -Id 'AZL-WDAC-002' -Category 'Application Control' -Severity 'Medium' `
        -Title 'Every WDAC supplemental policy is on the approved list' `
        -Rationale 'Supplemental policies are how third-party agents are allowed to run, and each one widens the trust boundary. An undocumented supplemental policy is an unreviewed exception, and it is exactly what breaks during an update.' `
        -Reference 'https://learn.microsoft.com/en-us/azure/azure-local/manage/manage-wdac' `
        -Test {
            param($Context)

            $approved = @()
            if ($Context.Parameters.ContainsKey('approvedPolicies')) {
                $approved = @($Context.Parameters['approvedPolicies'])
            }

            $probe = Get-AzLocalWdacPolicyInventory
            if (-not $probe.Ok) {
                return New-AzLocalCheckResult -Status Unknown -Expected 'Only approved supplemental policies' -Detail $probe.Message
            }

            $supplemental = @()
            foreach ($policy in @($probe.Value)) {
                if ($null -eq $policy) { continue }

                $nameProperty = $policy.PSObject.Properties['PolicyName']
                if (-not $nameProperty) { $nameProperty = $policy.PSObject.Properties['FriendlyName'] }
                $name = if ($nameProperty) { [string] $nameProperty.Value } else { [string] $policy }

                $isBase = $false
                $baseProperty = $policy.PSObject.Properties['IsSystemPolicy']
                if ($baseProperty) { $isBase = [bool] $baseProperty.Value }
                if ($name -like 'AS_Base_Policy*') { $isBase = $true }

                if (-not $isBase) { $supplemental += $name }
            }

            $unapproved = @($supplemental | Where-Object { $approved -notcontains $_ })
            $status = if ($unapproved.Count -eq 0) { 'Compliant' } else { 'NonCompliant' }

            return New-AzLocalCheckResult -Status $status `
                -Expected "approved: $(if ($approved.Count) { $approved -join ', ' } else { 'none' })" `
                -Actual "$($supplemental.Count) supplemental polic(y/ies) present" `
                -Detail $(if ($unapproved.Count) { "Unapproved: $($unapproved -join ', '). Document these or remove them." } else { 'All supplemental policies are on the approved list.' }) `
                -Evidence @{ Supplemental = $supplemental; Unapproved = $unapproved }
        }))

    #endregion

    #region Data at rest

    $controls.Add((New-AzLocalControl -Id 'AZL-BL-001' -Category 'Data at rest' -Severity 'Critical' `
        -Title 'Every boot volume is BitLocker encrypted' `
        -Rationale 'An unencrypted boot volume means a stolen or RMA-returned disk hands over the operating system, its configuration and any cached material on it.' `
        -Reference 'https://learn.microsoft.com/en-us/azure/azure-local/manage/manage-bitlocker' `
        -Test {
            param($Context)
            return Test-AzLocalBitLockerVolumeSet -VolumeType 'BootVolume' -Context $Context
        } `
        -Remediate {
            param($Context)
            $writeScope = if ($Context.Scope -eq 'Local') { 'Local' } else { 'Cluster' }
            return Enable-AzLocalBitLockerVolume -VolumeType 'BootVolume' -Scope $writeScope
        } -RequiresMaintenanceWindow))

    $controls.Add((New-AzLocalControl -Id 'AZL-BL-002' -Category 'Data at rest' -Severity 'Critical' `
        -Title 'Every Cluster Shared Volume is BitLocker encrypted' `
        -Rationale 'Volumes created after deployment do not inherit encryption. A CSV added six months into the cluster life is the usual gap, and it is the volume with the workload data on it.' `
        -Reference 'https://learn.microsoft.com/en-us/azure/azure-local/manage/manage-bitlocker' `
        -Test {
            param($Context)
            return Test-AzLocalBitLockerVolumeSet -VolumeType 'ClusterSharedVolume' -Context $Context
        } `
        -Remediate {
            param($Context)

            $writeScope = if ($Context.Scope -eq 'Local') { 'Local' } else { 'Cluster' }
            $mountPoint = $null
            if ($Context.Parameters.ContainsKey('mountPoint')) {
                $mountPoint = [string] $Context.Parameters['mountPoint']
            }

            if ($mountPoint) {
                return Enable-AzLocalBitLockerVolume -VolumeType 'ClusterSharedVolume' -Scope $writeScope -MountPoint $mountPoint
            }

            return Enable-AzLocalBitLockerVolume -VolumeType 'ClusterSharedVolume' -Scope $writeScope
        } -RequiresMaintenanceWindow))

    $controls.Add((New-AzLocalControl -Id 'AZL-BL-003' -Category 'Data at rest' -Severity 'High' `
        -Title 'BitLocker recovery keys are retrievable for every node' `
        -Rationale 'The platform escrows keys to Active Directory or Key Vault, which is a fine default until the disaster you need them for is the one that took out the directory. If this check cannot enumerate a key per node, your recovery path is untested.' `
        -Reference 'https://learn.microsoft.com/en-us/azure/azure-local/manage/manage-bitlocker' `
        -Test {
            param($Context)

            $probe = Get-AzLocalBitLockerRecoveryKey
            if (-not $probe.Ok) {
                return New-AzLocalCheckResult -Status Unknown -Expected 'At least one recovery key per node' -Detail $probe.Message
            }

            $keys = @($probe.Value | Where-Object { $_ })
            if ($keys.Count -eq 0) {
                return New-AzLocalCheckResult -Status NonCompliant -Expected 'At least one recovery key per node' `
                    -Actual '0 keys returned' `
                    -Detail 'Get-AsRecoveryKeyInfo returned nothing. Recovery is not possible from this path.'
            }

            $nodes = @($keys | ForEach-Object {
                $property = $_.PSObject.Properties['ComputerName']
                if ($property) { [string] $property.Value }
            } | Where-Object { $_ } | Select-Object -Unique)

            # Deliberately records counts and node names only. Recovery key
            # material is never written to a report or a log by this module.
            return New-AzLocalCheckResult -Status Compliant -Expected 'At least one recovery key per node' `
                -Actual "$($keys.Count) key(s) across $($nodes.Count) node(s)" `
                -Detail 'Keys are retrievable. Export them to a location that survives the loss of this cluster and the loss of the directory, then verify the restore path on a schedule.' `
                -Evidence @{ KeyCount = $keys.Count; Nodes = $nodes }
        }))

    #endregion

    #region Malware protection

    $controls.Add((New-AzLocalControl -Id 'AZL-AV-001' -Category 'Malware protection' -Severity 'High' `
        -Title 'Microsoft Defender real-time protection is active' `
        -Rationale 'Defender Antivirus ships enabled and configured. If real-time protection is off, something turned it off, and that is worth knowing about.' `
        -Reference 'https://learn.microsoft.com/en-us/azure/azure-local/concepts/security-features' `
        -Test {
            param($Context)

            $probe = Get-AzLocalDefenderStatus
            if (-not $probe.Ok) {
                return New-AzLocalCheckResult -Status Unknown -Expected $true -Detail $probe.Message
            }

            $status = $probe.Value
            $realTime = [bool] $status.RealTimeProtectionEnabled
            $antimalware = [bool] $status.AMServiceEnabled

            $result = if ($realTime -and $antimalware) { 'Compliant' } else { 'NonCompliant' }

            return New-AzLocalCheckResult -Status $result -Expected $true `
                -Actual "realTime=$realTime, service=$antimalware" `
                -Detail 'If a non-Microsoft antivirus is in use instead, confirm it is ISV-validated for Azure Local and that the documented exclusion paths are configured.' `
                -Evidence @{ RealTimeProtectionEnabled = $realTime; AMServiceEnabled = $antimalware }
        }))

    $controls.Add((New-AzLocalControl -Id 'AZL-AV-002' -Category 'Malware protection' -Severity 'Medium' `
        -Title 'Defender signatures are current' `
        -Rationale 'A cluster with stale signatures is usually a cluster that lost its outbound path to Microsoft Update, which means several other things are probably also failing quietly.' `
        -Reference 'https://learn.microsoft.com/en-us/azure/azure-local/concepts/security-features' `
        -Test {
            param($Context)

            $maxAgeDays = 3
            if ($Context.Parameters.ContainsKey('maxSignatureAgeDays')) {
                $maxAgeDays = [int] $Context.Parameters['maxSignatureAgeDays']
            }

            $probe = Get-AzLocalDefenderStatus
            if (-not $probe.Ok) {
                return New-AzLocalCheckResult -Status Unknown -Expected "age <= $maxAgeDays days" -Detail $probe.Message
            }

            $age = $probe.Value.AntivirusSignatureAge
            if ($null -eq $age) {
                return New-AzLocalCheckResult -Status Unknown -Expected "age <= $maxAgeDays days" `
                    -Detail 'Defender did not report a signature age.'
            }

            $age = [int] $age
            $status = if ($age -le $maxAgeDays) { 'Compliant' } else { 'NonCompliant' }

            return New-AzLocalCheckResult -Status $status -Expected "age <= $maxAgeDays days" -Actual "$age days" `
                -Evidence @{ AntivirusSignatureAge = $age }
        }))

    $controls.Add((New-AzLocalControl -Id 'AZL-AV-003' -Category 'Malware protection' -Severity 'Medium' `
        -Title 'Potentially unwanted application protection is enforced' `
        -Rationale 'PUA blocking was added to the Defender settings in the 2506 baseline. It catches the bundled remote-access and crypto-mining tooling that is technically legitimate and never belongs on a hypervisor host.' `
        -Reference 'https://learn.microsoft.com/en-us/azure/azure-local/whats-new' `
        -Test {
            param($Context)

            $probe = Get-AzLocalDefenderPreference
            if (-not $probe.Ok) {
                return New-AzLocalCheckResult -Status Unknown -Expected 'Enabled (1)' -Detail $probe.Message
            }

            $pua = $probe.Value.PUAProtection
            if ($null -eq $pua) {
                return New-AzLocalCheckResult -Status Unknown -Expected 'Enabled (1)' `
                    -Detail 'Get-MpPreference did not return PUAProtection.'
            }

            # 0 = disabled, 1 = block, 2 = audit
            $status = if ([int] $pua -eq 1) { 'Compliant' } else { 'NonCompliant' }

            return New-AzLocalCheckResult -Status $status -Expected 'Enabled (1)' -Actual $pua `
                -Detail 'A value of 2 is audit mode: detections are logged but nothing is blocked.'
        }))

    #endregion

    #region Logging

    $controls.Add((New-AzLocalControl -Id 'AZL-LOG-001' -Category 'Logging' -Severity 'High' `
        -Title 'Syslog forwarding to a SIEM is enabled' `
        -Rationale 'Security events that never leave the cluster cannot be correlated, cannot be retained beyond the local log and cannot be investigated after an incident that took the cluster with it.' `
        -Reference 'https://learn.microsoft.com/en-us/azure/azure-local/manage/manage-syslog-forwarding' `
        -Test {
            param($Context)

            $probe = Get-AzLocalSyslogForwarder -Scope $(if ($Context.Scope -eq 'Local') { 'Local' } else { 'Cluster' })
            if (-not $probe.Ok) {
                return New-AzLocalCheckResult -Status Unknown -Expected 'Configured server' -Detail $probe.Message
            }

            $config = @($probe.Value)[0]
            if (-not $config) {
                return New-AzLocalCheckResult -Status NonCompliant -Expected 'Configured server' -Actual 'none' `
                    -Detail 'No syslog forwarder configuration was returned.'
            }

            $serverProperty = $config.PSObject.Properties['ServerName']
            $server = if ($serverProperty) { [string] $serverProperty.Value } else { $null }

            $status = if ([string]::IsNullOrWhiteSpace($server)) { 'NonCompliant' } else { 'Compliant' }

            return New-AzLocalCheckResult -Status $status -Expected 'Configured server' -Actual $server `
                -Detail 'Verify end to end once a quarter: generate a known event and confirm it reaches the SIEM. A forwarder pointed at a decommissioned collector reports as healthy.' `
                -Evidence @{ ServerName = $server }
        }))

    $controls.Add((New-AzLocalControl -Id 'AZL-LOG-002' -Category 'Logging' -Severity 'High' `
        -Title 'Syslog forwarding uses TCP with TLS encryption' `
        -Rationale 'UDP and plain TCP send security events unauthenticated and in clear text. Those transports exist for lab testing and have a habit of surviving into production.' `
        -Reference 'https://learn.microsoft.com/en-us/azure/azure-local/manage/manage-syslog-forwarding' `
        -Test {
            param($Context)
            return Test-AzLocalSyslogTransport -Context $Context -RequireClientCertificate:$false
        }))

    $controls.Add((New-AzLocalControl -Id 'AZL-LOG-003' -Category 'Logging' -Severity 'Medium' `
        -Title 'Syslog forwarding uses mutual TLS authentication' `
        -Rationale 'Mutual authentication is the highest supported configuration and the only one where the collector can prove which node sent an event. Server-only authentication is acceptable; anything below it is not.' `
        -Reference 'https://learn.microsoft.com/en-us/azure/azure-local/manage/manage-syslog-forwarding' `
        -Test {
            param($Context)
            return Test-AzLocalSyslogTransport -Context $Context -RequireClientCertificate:$true
        }))

    #endregion

    #region Accounts and policy

    $controls.Add((New-AzLocalControl -Id 'AZL-ACC-001' -Category 'Accounts and policy' -Severity 'Medium' `
        -Title 'The well-known RID 500 administrator account is disabled' `
        -Rationale 'ASBuiltInAdmin is enabled by default and its SID is predictable, which makes it a free target for password spraying. Microsoft recommends creating a custom administrative account and disabling this one.' `
        -Reference 'https://learn.microsoft.com/en-us/azure/azure-local/concepts/security-features' `
        -Test {
            param($Context)
            return Test-AzLocalWellKnownAccount -Rid 500 -ExpectedEnabled $false
        }))

    $controls.Add((New-AzLocalControl -Id 'AZL-ACC-002' -Category 'Accounts and policy' -Severity 'High' `
        -Title 'The well-known RID 501 guest account is disabled' `
        -Rationale 'ASBuiltInGuest is disabled by default and drift control keeps it that way. If this check fails, either drift control is off or something re-enabled it deliberately.' `
        -Reference 'https://learn.microsoft.com/en-us/azure/azure-local/concepts/security-features' `
        -Test {
            param($Context)
            return Test-AzLocalWellKnownAccount -Rid 501 -ExpectedEnabled $false
        }))

    $controls.Add((New-AzLocalControl -Id 'AZL-PWD-001' -Category 'Accounts and policy' -Severity 'High' `
        -Title 'Minimum password length meets the baseline' `
        -Rationale 'The 2607 baseline raised the local minimum password length to 14 characters to align with the Azure Security Baseline and NIST guidance. Systems built on an earlier release can still be sitting on the old default.' `
        -Reference 'https://learn.microsoft.com/en-us/azure/azure-local/manage/manage-secure-baseline' `
        -Test {
            param($Context)

            $minimum = 14
            if ($Context.Parameters.ContainsKey('minimumLength')) {
                $minimum = [int] $Context.Parameters['minimumLength']
            }

            $probe = Get-AzLocalPasswordPolicy
            if (-not $probe.Ok) {
                return New-AzLocalCheckResult -Status Unknown -Expected ">= $minimum" -Detail $probe.Message
            }

            $actual = $probe.Value.MinimumPasswordLength
            if ($null -eq $actual) {
                return New-AzLocalCheckResult -Status Unknown -Expected ">= $minimum" `
                    -Detail 'Could not parse the minimum password length from net accounts output.'
            }

            $status = if ([int] $actual -ge $minimum) { 'Compliant' } else { 'NonCompliant' }

            return New-AzLocalCheckResult -Status $status -Expected ">= $minimum" -Actual $actual
        } `
        -Remediate {
            param($Context)

            $minimum = 14
            if ($Context.Parameters.ContainsKey('minimumLength')) {
                $minimum = [int] $Context.Parameters['minimumLength']
            }

            return Set-AzLocalPasswordPolicyLength -MinimumLength $minimum
        }))

    $controls.Add((New-AzLocalControl -Id 'AZL-BAN-001' -Category 'Accounts and policy' -Severity 'Low' `
        -Title 'An interactive logon legal notice is configured' `
        -Rationale 'Both DISA STIG and CIS ask for a logon banner, and the 2604 baseline ships one. The settings are drift-protected, so customising the wording means disabling drift control first, changing it, then turning drift control back on.' `
        -Reference 'https://learn.microsoft.com/en-us/azure/azure-local/manage/manage-secure-baseline' `
        -Test {
            param($Context)

            $path = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
            $captionProbe = Get-AzLocalRegistryValue -Path $path -Name 'LegalNoticeCaption'
            $textProbe = Get-AzLocalRegistryValue -Path $path -Name 'LegalNoticeText'

            if (-not $captionProbe.Ok -and -not $textProbe.Ok) {
                return New-AzLocalCheckResult -Status NonCompliant -Expected 'Caption and text set' -Actual 'neither set' `
                    -Detail 'Neither LegalNoticeCaption nor LegalNoticeText is present.'
            }

            $caption = if ($captionProbe.Ok) { [string] $captionProbe.Value } else { '' }
            $text = if ($textProbe.Ok) { [string] $textProbe.Value } else { '' }

            $hasBoth = -not ([string]::IsNullOrWhiteSpace($caption) -or [string]::IsNullOrWhiteSpace($text))
            $status = if ($hasBoth) { 'Compliant' } else { 'NonCompliant' }

            return New-AzLocalCheckResult -Status $status -Expected 'Caption and text set' `
                -Actual "caption='$caption', text length=$($text.Length)"
        } `
        -Remediate {
            param($Context)

            $path = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
            $caption = 'Authorised use only'
            $text = 'This system is restricted to authorised users. Activity is logged and monitored.'

            if ($Context.Parameters.ContainsKey('caption')) { $caption = [string] $Context.Parameters['caption'] }
            if ($Context.Parameters.ContainsKey('text')) { $text = [string] $Context.Parameters['text'] }

            $first = Set-AzLocalRegistryValue -Path $path -Name 'LegalNoticeCaption' -Value $caption
            if (-not $first.Ok) { return $first }

            return Set-AzLocalRegistryValue -Path $path -Name 'LegalNoticeText' -Value $text
        }))

    #endregion

    #region Lifecycle

    $controls.Add((New-AzLocalControl -Id 'AZL-UPD-001' -Category 'Lifecycle' -Severity 'High' `
        -Title 'The solution update environment is healthy' `
        -Rationale 'The security baseline itself ships with the release. A cluster that has drifted off the release train is not just missing patches, it is running an older definition of what secure means.' `
        -Reference 'https://learn.microsoft.com/en-us/azure/azure-local/update/update-via-powershell-23h2' `
        -Test {
            param($Context)

            $probe = Get-AzLocalSolutionUpdateEnvironment
            if (-not $probe.Ok) {
                return New-AzLocalCheckResult -Status Unknown -Expected 'HealthState = Success' -Detail $probe.Message
            }

            $environment = @($probe.Value)[0]
            if (-not $environment) {
                return New-AzLocalCheckResult -Status Unknown -Expected 'HealthState = Success' `
                    -Detail 'Get-SolutionUpdateEnvironment returned nothing.'
            }

            $healthProperty = $environment.PSObject.Properties['HealthState']
            $health = if ($healthProperty) { [string] $healthProperty.Value } else { $null }

            $versionProperty = $environment.PSObject.Properties['CurrentVersion']
            $version = if ($versionProperty) { [string] $versionProperty.Value } else { 'unknown' }

            if ([string]::IsNullOrWhiteSpace($health)) {
                return New-AzLocalCheckResult -Status Unknown -Expected 'HealthState = Success' `
                    -Detail 'No HealthState was reported.' -Evidence @{ CurrentVersion = $version }
            }

            $status = if ($health -match '^(?i)(success|healthy)$') { 'Compliant' } else { 'NonCompliant' }

            return New-AzLocalCheckResult -Status $status -Expected 'HealthState = Success' -Actual $health `
                -Detail "Current solution version: $version." `
                -Evidence @{ CurrentVersion = $version; HealthState = $health }
        }))

    #endregion

    $script:ControlRegistryCache = $controls.ToArray()
    return $script:ControlRegistryCache
}

#region Shared test helpers

function Test-AzLocalBitLockerVolumeSet {
    <#
        .SYNOPSIS
            Shared evaluation for the boot volume and CSV BitLocker controls.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('BootVolume', 'ClusterSharedVolume')]
        [string] $VolumeType,

        [Parameter(Mandatory)]
        [hashtable] $Context
    )

    $readScope = if ($Context.Scope -eq 'Local') { 'Local' } else { 'PerNode' }
    $probe = Get-AzLocalBitLockerVolume -VolumeType $VolumeType -Scope $readScope

    if (-not $probe.Ok) {
        return New-AzLocalCheckResult -Status Unknown -Expected 'All volumes protected' -Detail $probe.Message
    }

    $volumes = @($probe.Value | Where-Object { $_ })
    if ($volumes.Count -eq 0) {
        return New-AzLocalCheckResult -Status Unknown -Expected 'All volumes protected' -Actual 'no volumes returned' `
            -Detail "Get-ASBitLocker returned no $VolumeType entries."
    }

    $unprotected = @()
    foreach ($volume in $volumes) {
        $statusProperty = $volume.PSObject.Properties['ProtectionStatus']
        if (-not $statusProperty) { $statusProperty = $volume.PSObject.Properties['VolumeStatus'] }

        $mountProperty = $volume.PSObject.Properties['MountPoint']
        $mount = if ($mountProperty) { [string] $mountProperty.Value } else { '(unnamed volume)' }

        $isProtected = $false
        if ($statusProperty) {
            $value = $statusProperty.Value
            if ($value -is [bool]) {
                $isProtected = $value
            }
            else {
                $isProtected = ([string] $value) -match '^(?i)(on|fullyencrypted|protectionon|1|true)$'
            }
        }

        if (-not $isProtected) { $unprotected += $mount }
    }

    $status = if ($unprotected.Count -eq 0) { 'Compliant' } else { 'NonCompliant' }

    return New-AzLocalCheckResult -Status $status -Expected 'All volumes protected' `
        -Actual "$($volumes.Count - $unprotected.Count)/$($volumes.Count) protected" `
        -Detail $(if ($unprotected.Count) {
            "Unprotected: $($unprotected -join ', '). Enabling encryption pauses virtual machines during the initial phases, so schedule a maintenance window."
        } else {
            'All returned volumes report protection on.'
        }) `
        -Evidence @{ VolumeType = $VolumeType; Unprotected = $unprotected; Total = $volumes.Count }
}

function Test-AzLocalSyslogTransport {
    <#
        .SYNOPSIS
            Shared evaluation for the syslog transport security controls.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Context,

        [switch] $RequireClientCertificate
    )

    $expected = if ($RequireClientCertificate) { 'TCP + TLS + client certificate' } else { 'TCP + TLS' }

    $probe = Get-AzLocalSyslogForwarder -Scope $(if ($Context.Scope -eq 'Local') { 'Local' } else { 'Cluster' })
    if (-not $probe.Ok) {
        return New-AzLocalCheckResult -Status Unknown -Expected $expected -Detail $probe.Message
    }

    $config = @($probe.Value)[0]
    if (-not $config) {
        return New-AzLocalCheckResult -Status NonCompliant -Expected $expected -Actual 'not configured' `
            -Detail 'No syslog forwarder configuration was returned.'
    }

    $readFlag = {
        param($Object, $Name)
        $property = $Object.PSObject.Properties[$Name]
        if ($property) { return $property.Value }
        return $null
    }

    $useUdp = [bool] (& $readFlag $config 'UseUDP')
    $noEncryption = [bool] (& $readFlag $config 'NoEncryption')
    $skipServerCheck = [bool] (& $readFlag $config 'SkipServerCertificateCheck')
    $skipCnCheck = [bool] (& $readFlag $config 'SkipServerCNCheck')
    $clientThumbprint = [string] (& $readFlag $config 'ClientCertificateThumbprint')

    $problems = @()
    if ($useUdp) { $problems += 'UDP transport' }
    if ($noEncryption) { $problems += 'encryption disabled' }
    if ($skipServerCheck) { $problems += 'server certificate validation skipped' }
    if ($skipCnCheck) { $problems += 'server CN validation skipped' }

    if ($RequireClientCertificate -and [string]::IsNullOrWhiteSpace($clientThumbprint)) {
        $problems += 'no client certificate thumbprint'
    }

    $status = if ($problems.Count -eq 0) { 'Compliant' } else { 'NonCompliant' }

    $actual = if ($useUdp) { 'UDP' } else { 'TCP' }
    if ($noEncryption) { $actual += ', unencrypted' } else { $actual += ', TLS' }
    if ($clientThumbprint) { $actual += ', client cert present' }

    return New-AzLocalCheckResult -Status $status -Expected $expected -Actual $actual `
        -Detail $(if ($problems.Count) { "Findings: $($problems -join '; ')." } else { 'Transport meets the recommended configuration.' }) `
        -Evidence @{
            UseUDP                     = $useUdp
            NoEncryption               = $noEncryption
            SkipServerCertificateCheck = $skipServerCheck
            SkipServerCNCheck          = $skipCnCheck
            HasClientCertificate       = -not [string]::IsNullOrWhiteSpace($clientThumbprint)
        }
}

function Test-AzLocalWellKnownAccount {
    <#
        .SYNOPSIS
            Shared evaluation for the well-known RID 500 and 501 account controls.

        .DESCRIPTION
            Matching is by RID rather than by account name, because the built-in
            accounts can be renamed and frequently are.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [int] $Rid,

        [Parameter(Mandatory)]
        [bool] $ExpectedEnabled
    )

    $expected = "RID $Rid $(if ($ExpectedEnabled) { 'enabled' } else { 'disabled' })"

    $probe = Get-AzLocalLocalUser
    if (-not $probe.Ok) {
        return New-AzLocalCheckResult -Status Unknown -Expected $expected -Detail $probe.Message
    }

    $account = @($probe.Value | Where-Object { $_.Rid -eq $Rid })[0]
    if (-not $account) {
        return New-AzLocalCheckResult -Status NotApplicable -Expected $expected -Actual 'account not present' `
            -Detail "No local account with RID $Rid was found on this host."
    }

    $compliant = ([bool] $account.Enabled -eq $ExpectedEnabled)
    $status = if ($compliant) { 'Compliant' } else { 'NonCompliant' }

    $detail = if ($compliant) {
        "$($account.Name) (RID $Rid) is in the expected state."
    }
    elseif ($Rid -eq 500) {
        'Disabling a built-in administrator is deliberately not automated here. Create a replacement administrative account, verify you can sign in with it and that lifecycle operations still work, then disable this one.'
    }
    else {
        "$($account.Name) (RID $Rid) is enabled. This account is disabled by default and protected by drift control, so something turned it on deliberately. Find out what before disabling it again."
    }

    return New-AzLocalCheckResult -Status $status -Expected $expected `
        -Actual "$($account.Name) is $(if ($account.Enabled) { 'enabled' } else { 'disabled' })" `
        -Detail $detail `
        -Evidence @{ Name = $account.Name; Rid = $account.Rid; Enabled = [bool] $account.Enabled }
}

#endregion
