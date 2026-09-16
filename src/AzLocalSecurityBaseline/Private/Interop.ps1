#requires -Version 5.1
<#
    Interop.ps1

    Every call into a native Azure Local, Windows or Defender cmdlet goes through a
    thin wrapper in this file. Nothing else in the module touches those cmdlets
    directly.

    Two reasons for the indirection:

      1. Pester can mock these wrappers, so the control logic is unit-testable on a
         machine that has never seen an Azure Local cluster.
      2. Every probe is failure-tolerant in one place. A missing cmdlet, an
         unreachable node or a CredSSP refusal becomes a structured "Unknown"
         result rather than a terminating error that aborts an audit run.
#>

function Test-AzLocalCommand {
    <#
        .SYNOPSIS
            Returns $true when a command exists in the current session.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string] $Name
    )

    return [bool](Get-Command -Name $Name -ErrorAction SilentlyContinue)
}

function Invoke-AzLocalProbe {
    <#
        .SYNOPSIS
            Runs a probe scriptblock and normalises success, absence and failure.

        .DESCRIPTION
            Returns a probe result object:

                Ok        : the scriptblock ran without a terminating error
                Value     : whatever the scriptblock returned
                Reason    : why Ok is $false ('MissingCommand', 'Error')
                Message   : the exception message, when there was one

            A probe never throws. Callers decide whether a failed probe means
            NonCompliant or Unknown, and for a security audit the honest answer is
            almost always Unknown.

        .PARAMETER RequiredCommand
            Commands that must exist before the scriptblock is worth running.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [scriptblock] $ScriptBlock,

        [string[]] $RequiredCommand = @(),

        [string] $Description = 'probe'
    )

    foreach ($command in $RequiredCommand) {
        if (-not (Test-AzLocalCommand -Name $command)) {
            Write-AzLocalLog -Level Debug -Message "Skipping $Description : '$command' is not available on this host."
            return [pscustomobject]@{
                Ok      = $false
                Value   = $null
                Reason  = 'MissingCommand'
                Message = "The cmdlet '$command' is not available. Run this on an Azure Local node, or install the module that provides it."
            }
        }
    }

    try {
        $value = & $ScriptBlock
        return [pscustomobject]@{
            Ok      = $true
            Value   = $value
            Reason  = $null
            Message = $null
        }
    }
    catch {
        Write-AzLocalLog -Level Debug -Message "Probe '$Description' failed: $($_.Exception.Message)"
        return [pscustomobject]@{
            Ok      = $false
            Value   = $null
            Reason  = 'Error'
            Message = $_.Exception.Message
        }
    }
}

#region Security feature interop (Get-AzsSecurity / Enable-AzsSecurity / Disable-AzsSecurity)

function Get-AzLocalSecurityFeature {
    <#
        .SYNOPSIS
            Reads one drift-protected security feature.

        .PARAMETER FeatureName
            VBS, CredentialGuard, DRTM, HVCI, SideChannelMitigation, SMBSigning,
            SMBClusterEncryption or DriftControl.

        .PARAMETER Scope
            Local   : this node only (no CredSSP needed)
            Cluster : the value held by the orchestrator (ECE store)
            AllNodes: the computed value across every node
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $FeatureName,

        [ValidateSet('Local', 'Cluster', 'AllNodes', 'PerNode')]
        [string] $Scope = 'Local'
    )

    $splat = @{ FeatureName = $FeatureName; $Scope = $true }

    return Invoke-AzLocalProbe -Description "Get-AzsSecurity $FeatureName ($Scope)" `
        -RequiredCommand 'Get-AzsSecurity' -ScriptBlock {
            Get-AzsSecurity @splat
        }.GetNewClosure()
}

function Set-AzLocalSecurityFeature {
    <#
        .SYNOPSIS
            Enables or disables a drift-protected security feature.

        .NOTES
            ShouldProcess is handled by the calling public function, not here, so
            that -WhatIf output names the control rather than the cmdlet.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $FeatureName,

        [Parameter(Mandatory)]
        [bool] $Enabled,

        [ValidateSet('Local', 'Cluster')]
        [string] $Scope = 'Cluster'
    )

    $command = if ($Enabled) { 'Enable-AzsSecurity' } else { 'Disable-AzsSecurity' }
    $splat = @{ FeatureName = $FeatureName; $Scope = $true }

    return Invoke-AzLocalProbe -Description "$command $FeatureName ($Scope)" `
        -RequiredCommand $command -ScriptBlock {
            & $command @splat
        }.GetNewClosure()
}

#endregion

#region Application Control interop

function Get-AzLocalWdacMode {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    return Invoke-AzLocalProbe -Description 'Get-AsWdacPolicyMode' `
        -RequiredCommand 'Get-AsWdacPolicyMode' -ScriptBlock {
            Get-AsWdacPolicyMode
        }
}

function Set-AzLocalWdacMode {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Audit', 'Enforced')]
        [string] $Mode
    )

    return Invoke-AzLocalProbe -Description "Enable-AsWdacPolicy -Mode $Mode" `
        -RequiredCommand 'Enable-AsWdacPolicy' -ScriptBlock {
            Enable-AsWdacPolicy -Mode $Mode
        }.GetNewClosure()
}

function Get-AzLocalWdacPolicyInventory {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    return Invoke-AzLocalProbe -Description 'Get-ASLocalWDACPolicyInfo' `
        -RequiredCommand 'Get-ASLocalWDACPolicyInfo' -ScriptBlock {
            Get-ASLocalWDACPolicyInfo
        }
}

#endregion

#region BitLocker interop

function Get-AzLocalBitLockerVolume {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('BootVolume', 'ClusterSharedVolume')]
        [string] $VolumeType,

        [ValidateSet('Local', 'PerNode', 'Cluster')]
        [string] $Scope = 'Local'
    )

    $splat = @{ VolumeType = $VolumeType; $Scope = $true }

    return Invoke-AzLocalProbe -Description "Get-ASBitLocker $VolumeType ($Scope)" `
        -RequiredCommand 'Get-ASBitLocker' -ScriptBlock {
            Get-ASBitLocker @splat
        }.GetNewClosure()
}

function Enable-AzLocalBitLockerVolume {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('BootVolume', 'ClusterSharedVolume')]
        [string] $VolumeType,

        [string] $MountPoint,

        [ValidateSet('Local', 'Cluster')]
        [string] $Scope = 'Local'
    )

    $splat = @{ VolumeType = $VolumeType; $Scope = $true }
    if ($MountPoint) { $splat['MountPoint'] = $MountPoint }

    return Invoke-AzLocalProbe -Description "Enable-ASBitLocker $VolumeType ($Scope)" `
        -RequiredCommand 'Enable-ASBitLocker' -ScriptBlock {
            Enable-ASBitLocker @splat
        }.GetNewClosure()
}

function Get-AzLocalBitLockerRecoveryKey {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    return Invoke-AzLocalProbe -Description 'Get-AsRecoveryKeyInfo' `
        -RequiredCommand 'Get-AsRecoveryKeyInfo' -ScriptBlock {
            Get-AsRecoveryKeyInfo
        }
}

#endregion

#region Syslog interop

function Get-AzLocalSyslogForwarder {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [ValidateSet('Local', 'PerNode', 'Cluster')]
        [string] $Scope = 'Cluster'
    )

    $splat = @{ $Scope = $true }

    return Invoke-AzLocalProbe -Description "Get-AzSSyslogForwarder ($Scope)" `
        -RequiredCommand 'Get-AzSSyslogForwarder' -ScriptBlock {
            Get-AzSSyslogForwarder @splat
        }.GetNewClosure()
}

#endregion

#region Platform interop

function Get-AzLocalDefenderStatus {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    return Invoke-AzLocalProbe -Description 'Get-MpComputerStatus' `
        -RequiredCommand 'Get-MpComputerStatus' -ScriptBlock {
            Get-MpComputerStatus
        }
}

function Get-AzLocalDefenderPreference {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    return Invoke-AzLocalProbe -Description 'Get-MpPreference' `
        -RequiredCommand 'Get-MpPreference' -ScriptBlock {
            Get-MpPreference
        }
}

function Get-AzLocalTpm {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    return Invoke-AzLocalProbe -Description 'Get-Tpm' `
        -RequiredCommand 'Get-Tpm' -ScriptBlock {
            Get-Tpm
        }
}

function Get-AzLocalSecureBootState {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    return Invoke-AzLocalProbe -Description 'Confirm-SecureBootUEFI' `
        -RequiredCommand 'Confirm-SecureBootUEFI' -ScriptBlock {
            Confirm-SecureBootUEFI
        }
}

function Get-AzLocalSolutionUpdateEnvironment {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    return Invoke-AzLocalProbe -Description 'Get-SolutionUpdateEnvironment' `
        -RequiredCommand 'Get-SolutionUpdateEnvironment' -ScriptBlock {
            Get-SolutionUpdateEnvironment
        }
}

function Get-AzLocalPasswordPolicy {
    <#
        .SYNOPSIS
            Reads the effective local password policy.

        .DESCRIPTION
            'net accounts' is used rather than the ActiveDirectory module because
            this has to work on an AD-less deployment as well as a domain-joined
            one, and because the baseline's 14-character rule is a local policy.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    return Invoke-AzLocalProbe -Description 'net accounts' -ScriptBlock {
        $raw = & net.exe accounts 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "net accounts exited with code $LASTEXITCODE."
        }

        $minimum = $null
        foreach ($line in $raw) {
            if ($line -match 'Minimum password length\s*:\s*(\d+)') {
                $minimum = [int] $Matches[1]
                break
            }
        }

        [pscustomobject]@{
            MinimumPasswordLength = $minimum
            Raw                   = ($raw -join [Environment]::NewLine)
        }
    }
}

function Get-AzLocalLocalUser {
    <#
        .SYNOPSIS
            Returns local accounts with their RID, so the well-known 500 and 501
            accounts can be identified without depending on their display names.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    return Invoke-AzLocalProbe -Description 'Get-LocalUser' `
        -RequiredCommand 'Get-LocalUser' -ScriptBlock {
            Get-LocalUser | ForEach-Object {
                $rid = $null
                if ($_.SID -and $_.SID.Value -match '-(\d+)$') {
                    $rid = [int] $Matches[1]
                }

                [pscustomobject]@{
                    Name    = $_.Name
                    Enabled = $_.Enabled
                    Sid     = if ($_.SID) { $_.SID.Value } else { $null }
                    Rid     = $rid
                }
            }
        }
}

function Get-AzLocalRegistryValue {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [string] $Name
    )

    return Invoke-AzLocalProbe -Description "Registry $Path\$Name" -ScriptBlock {
        $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        $item.$Name
    }.GetNewClosure()
}

function Set-AzLocalRegistryValue {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter(Mandatory)]
        $Value
    )

    return Invoke-AzLocalProbe -Description "Set registry $Path\$Name" -ScriptBlock {
        if (-not (Test-Path -Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force
    }.GetNewClosure()
}

function Set-AzLocalPasswordPolicyLength {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateRange(0, 128)]
        [int] $MinimumLength
    )

    return Invoke-AzLocalProbe -Description "net accounts /minpwlen:$MinimumLength" -ScriptBlock {
        $output = & net.exe accounts "/minpwlen:$MinimumLength" 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "net accounts /minpwlen failed: $($output -join ' ')"
        }
        $output
    }.GetNewClosure()
}

#endregion
