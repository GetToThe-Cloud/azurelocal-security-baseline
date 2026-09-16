#requires -Version 5.1

function Get-AzLocalSecurityState {
    <#
        .SYNOPSIS
            Collects the raw security state of an Azure Local system. Read-only.

        .DESCRIPTION
            Where Test-AzLocalSecurityBaseline gives you pass and fail against a
            desired state, this gives you the underlying facts: what every probe
            actually returned. Use it to investigate a finding, to capture a
            point-in-time snapshot before a change, or to attach evidence to a
            change record.

            No secret material is collected. The BitLocker section records how
            many recovery keys exist and on which nodes, never the keys.

        .PARAMETER Scope
            Local, Cluster or AllNodes. AllNodes needs CredSSP or a direct RDP
            session to a node.

        .EXAMPLE
            Get-AzLocalSecurityState -Scope Cluster |
                ConvertTo-Json -Depth 8 |
                Set-Content .\pre-change-state.json

        .OUTPUTS
            AzLocal.SecurityState
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [ValidateSet('Local', 'Cluster', 'AllNodes')]
        [string] $Scope = 'Local'
    )

    Write-AzLocalLog -Message "Collecting raw security state at scope '$Scope'."

    $featureNames = @(
        'DriftControl', 'VBS', 'HVCI', 'CredentialGuard',
        'DRTM', 'SideChannelMitigation', 'SMBSigning', 'SMBClusterEncryption'
    )

    $features = [ordered]@{}
    foreach ($name in $featureNames) {
        $probe = Get-AzLocalSecurityFeature -FeatureName $name -Scope $Scope
        $features[$name] = [pscustomobject]@{
            Value   = if ($probe.Ok) { Resolve-AzLocalFeatureValue -Value $probe.Value } else { $null }
            Raw     = if ($probe.Ok) { $probe.Value } else { $null }
            Ok      = $probe.Ok
            Message = $probe.Message
        }
    }

    $wdacMode = Get-AzLocalWdacMode
    $wdacPolicies = Get-AzLocalWdacPolicyInventory

    $readScope = if ($Scope -eq 'Local') { 'Local' } else { 'PerNode' }
    $bootVolumes = Get-AzLocalBitLockerVolume -VolumeType 'BootVolume' -Scope $readScope
    $csvVolumes = Get-AzLocalBitLockerVolume -VolumeType 'ClusterSharedVolume' -Scope $readScope
    $recoveryKeys = Get-AzLocalBitLockerRecoveryKey

    $recoveryKeySummary = $null
    if ($recoveryKeys.Ok) {
        $keys = @($recoveryKeys.Value | Where-Object { $_ })
        $recoveryKeySummary = [pscustomobject]@{
            KeyCount = $keys.Count
            Nodes    = @($keys | ForEach-Object {
                $property = $_.PSObject.Properties['ComputerName']
                if ($property) { [string] $property.Value }
            } | Where-Object { $_ } | Select-Object -Unique)
        }
    }

    $syslog = Get-AzLocalSyslogForwarder -Scope $(if ($Scope -eq 'Local') { 'Local' } else { 'Cluster' })
    $defenderStatus = Get-AzLocalDefenderStatus
    $defenderPreference = Get-AzLocalDefenderPreference
    $tpm = Get-AzLocalTpm
    $secureBoot = Get-AzLocalSecureBootState
    $updates = Get-AzLocalSolutionUpdateEnvironment
    $passwordPolicy = Get-AzLocalPasswordPolicy
    $localUsers = Get-AzLocalLocalUser

    return [pscustomobject]@{
        PSTypeName   = 'AzLocal.SecurityState'
        TimestampUtc = (Get-Date).ToUniversalTime()
        ComputerName = $env:COMPUTERNAME
        Scope        = $Scope

        Hardware = [pscustomobject]@{
            TpmPresent = if ($tpm.Ok) { [bool] $tpm.Value.TpmPresent } else { $null }
            TpmReady   = if ($tpm.Ok) { [bool] $tpm.Value.TpmReady } else { $null }
            SecureBoot = if ($secureBoot.Ok) { [bool] $secureBoot.Value } else { $null }
            Errors     = @(
                if (-not $tpm.Ok) { "TPM: $($tpm.Message)" }
                if (-not $secureBoot.Ok) { "Secure Boot: $($secureBoot.Message)" }
            ) | Where-Object { $_ }
        }

        SecurityFeatures = [pscustomobject] $features

        ApplicationControl = [pscustomobject]@{
            Mode     = if ($wdacMode.Ok) { $wdacMode.Value } else { $null }
            Policies = if ($wdacPolicies.Ok) { $wdacPolicies.Value } else { $null }
            Errors   = @(
                if (-not $wdacMode.Ok) { $wdacMode.Message }
                if (-not $wdacPolicies.Ok) { $wdacPolicies.Message }
            ) | Where-Object { $_ }
        }

        BitLocker = [pscustomobject]@{
            BootVolumes         = if ($bootVolumes.Ok) { $bootVolumes.Value } else { $null }
            ClusterSharedVolumes = if ($csvVolumes.Ok) { $csvVolumes.Value } else { $null }
            RecoveryKeySummary  = $recoveryKeySummary
            Errors              = @(
                if (-not $bootVolumes.Ok) { "Boot volumes: $($bootVolumes.Message)" }
                if (-not $csvVolumes.Ok) { "CSVs: $($csvVolumes.Message)" }
                if (-not $recoveryKeys.Ok) { "Recovery keys: $($recoveryKeys.Message)" }
            ) | Where-Object { $_ }
        }

        Syslog = [pscustomobject]@{
            Configuration = if ($syslog.Ok) { $syslog.Value } else { $null }
            Error         = $syslog.Message
        }

        Defender = [pscustomobject]@{
            RealTimeProtectionEnabled = if ($defenderStatus.Ok) { [bool] $defenderStatus.Value.RealTimeProtectionEnabled } else { $null }
            AntivirusSignatureAge     = if ($defenderStatus.Ok) { $defenderStatus.Value.AntivirusSignatureAge } else { $null }
            PUAProtection             = if ($defenderPreference.Ok) { $defenderPreference.Value.PUAProtection } else { $null }
            Errors                    = @(
                if (-not $defenderStatus.Ok) { $defenderStatus.Message }
                if (-not $defenderPreference.Ok) { $defenderPreference.Message }
            ) | Where-Object { $_ }
        }

        Lifecycle = [pscustomobject]@{
            UpdateEnvironment = if ($updates.Ok) { $updates.Value } else { $null }
            Error             = $updates.Message
        }

        Accounts = [pscustomobject]@{
            MinimumPasswordLength = if ($passwordPolicy.Ok) { $passwordPolicy.Value.MinimumPasswordLength } else { $null }
            WellKnownAccounts     = if ($localUsers.Ok) {
                @($localUsers.Value | Where-Object { $_.Rid -in @(500, 501) })
            } else { $null }
            Errors                = @(
                if (-not $passwordPolicy.Ok) { $passwordPolicy.Message }
                if (-not $localUsers.Ok) { $localUsers.Message }
            ) | Where-Object { $_ }
        }
    }
}
