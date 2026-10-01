#requires -Version 5.1

function Set-AzLocalSecurityBaseline {
    <#
        .SYNOPSIS
            Remediates non-compliant controls. Opt-in, and refuses to touch
            anything disruptive without being told to.

        .DESCRIPTION
            Audits first, then remediates only the controls that came back
            NonCompliant and that have a remediation defined.

            Three safety rules are deliberate and are not negotiable through the
            configuration file:

              1. Nothing runs without -Confirm being satisfied. The function
                 supports -WhatIf and defaults to ConfirmImpact High.
              2. Controls whose remediation reboots a node are skipped unless
                 -AllowReboot is supplied.
              3. Controls whose remediation pauses workloads, such as BitLocker
                 encryption of an existing volume, are skipped unless
                 -AllowMaintenanceWindow is supplied.

            A control reporting Unknown is never remediated. If the module could
            not read the current state, it has no business writing a new one.

        .PARAMETER ConfigPath
            Path to a JSON configuration file, merged over the shipped default.

        .PARAMETER Scope
            Local, Cluster or AllNodes. Cluster-wide writes need CredSSP or a
            direct delegated session to a node.

        .PARAMETER Target
            Optional remote target created with New-AzLocalSecurityRemoteTarget.
            WinRM supports all scopes when delegation is available; Arc Run
            Command is limited to Local.

        .PARAMETER ControlId
            Remediate only these control IDs. Wildcards are supported.

        .PARAMETER AllowReboot
            Permit remediations that require a reboot to take effect. The reboot
            itself is never performed by this module.

        .PARAMETER AllowMaintenanceWindow
            Permit remediations that pause workloads while they run.

        .PARAMETER Result
            Pre-computed audit results from Test-AzLocalSecurityBaseline. Supply
            these to remediate exactly what a previous audit found, rather than
            re-reading state that may have changed in between.

        .EXAMPLE
            Set-AzLocalSecurityBaseline -Scope Cluster -WhatIf

            Shows every change that would be made and makes none of them. Always
            the first run.

        .EXAMPLE
            Set-AzLocalSecurityBaseline -ControlId 'AZL-WDAC-001' -Scope Cluster

            Puts Application Control back into Enforced mode after a supplemental
            policy has been deployed, and changes nothing else.

        .EXAMPLE
            $audit = Test-AzLocalSecurityBaseline -Scope Cluster
            $audit | Where-Object Status -eq 'NonCompliant' | Format-Table Id, Title
            Set-AzLocalSecurityBaseline -Result $audit -Scope Cluster -AllowReboot

            Review, then act on exactly what was reviewed.

        .OUTPUTS
            AzLocal.RemediationResult
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
    param(
        [string] $ConfigPath,

        [ValidateSet('Local', 'Cluster')]
        [string] $Scope = 'Local',

        [string[]] $ControlId,

        [switch] $AllowReboot,

        [switch] $AllowMaintenanceWindow,

        [Parameter(ValueFromPipeline)]
        [psobject[]] $Result,

        [psobject] $Target
    )

    begin {
        $remoteMode = $null -ne $Target
        if (-not $remoteMode) {
            $config = Import-AzLocalBaselineConfig -Path $ConfigPath
            $runContext = Get-AzLocalRunContext -Config $config -Scope $Scope -ConfigPath $ConfigPath
        }
        $collected = New-Object System.Collections.Generic.List[object]
        $rebootPending = New-Object System.Collections.Generic.List[string]
    }

    process {
        if ($Result) {
            foreach ($item in $Result) { $collected.Add($item) }
        }
    }

    end {
        $audit = $collected.ToArray()

        if ($remoteMode) {
            $explicitConfirmFalse = $PSBoundParameters.ContainsKey('Confirm') -and -not $Confirm
            if (-not $WhatIfPreference -and -not $explicitConfirmFalse) {
                $remoteTargetName = Get-AzLocalRemoteTargetLabel -Target $Target
                if (-not $PSCmdlet.ShouldProcess($remoteTargetName, 'Run remote Azure Local security remediation')) {
                    return
                }
            }

            $remoteSplat = @{
                Operation              = 'Set'
                Target                 = $Target
                Scope                  = $Scope
                ConfigPath             = $ConfigPath
                ControlId              = $ControlId
                AllowReboot            = $AllowReboot
                AllowMaintenanceWindow = $AllowMaintenanceWindow
                Simulate               = $WhatIfPreference
                Result                 = $audit
            }
            Invoke-AzLocalRemoteOperation @remoteSplat
            return
        }

        if ($audit.Count -eq 0) {
            Write-AzLocalLog -Message 'No audit results supplied. Running an audit first.'
            $auditSplat = @{ Scope = $Scope }
            if ($ConfigPath) { $auditSplat['ConfigPath'] = $ConfigPath }
            if ($ControlId) { $auditSplat['ControlId'] = $ControlId }
            $audit = @(Test-AzLocalSecurityBaseline @auditSplat)
        }
        elseif ($ControlId) {
            $audit = @($audit | Where-Object {
                $item = $_
                @($ControlId | Where-Object { $item.Id -like $_ }).Count -gt 0
            })
        }

        $controls = @{}
        foreach ($control in (Get-AzLocalControlRegistry)) { $controls[$control.Id] = $control }

        $targets = @($audit | Where-Object { $_.Status -eq 'NonCompliant' })

        if ($targets.Count -eq 0) {
            Write-AzLocalLog -Message 'Nothing to remediate. Every evaluated control is compliant, unknown or skipped.'
            return
        }

        Write-AzLocalLog -Message "$($targets.Count) non-compliant control(s) to consider."

        foreach ($finding in $targets) {
            $control = $controls[$finding.Id]

            if (-not $control) {
                Write-AzLocalLog -Level Warning -Message "Unknown control '$($finding.Id)' in the supplied results. Skipping."
                continue
            }

            if (-not $control.Remediable) {
                New-AzLocalRemediationResult -Control $control -RunContext $runContext -Outcome 'NotSupported' `
                    -Message 'No automated remediation exists for this control. It needs a person.'
                continue
            }

            if ($control.RequiresReboot -and -not $AllowReboot) {
                New-AzLocalRemediationResult -Control $control -RunContext $runContext -Outcome 'Skipped' `
                    -Message 'Requires a reboot to take effect. Re-run with -AllowReboot inside a maintenance window.'
                continue
            }

            if ($control.RequiresMaintenanceWindow -and -not $AllowMaintenanceWindow) {
                New-AzLocalRemediationResult -Control $control -RunContext $runContext -Outcome 'Skipped' `
                    -Message 'Pauses workloads while it runs. Re-run with -AllowMaintenanceWindow inside a maintenance window.'
                continue
            }

            $target = "$($control.Id) on $($runContext.ComputerName) (scope: $Scope)"
            $action = "Remediate: $($control.Title)"

            if (-not $PSCmdlet.ShouldProcess($target, $action)) {
                New-AzLocalRemediationResult -Control $control -RunContext $runContext -Outcome 'WhatIf' `
                    -Message "Would remediate. Current state: $(ConvertTo-AzLocalDisplayValue -Value $finding.Actual)."
                continue
            }

            $setting = Get-AzLocalControlSetting -Config $config -ControlId $control.Id
            $controlContext = @{
                Config     = $config
                Scope      = $Scope
                Parameters = $setting.Parameters
                Data       = $control.Data
            }

            Write-AzLocalLog -Message "Remediating $($control.Id): $($control.Title)"

            $probe = $null
            try {
                $probe = & $control.Remediate $controlContext
            }
            catch {
                New-AzLocalRemediationResult -Control $control -RunContext $runContext -Outcome 'Failed' `
                    -Message $_.Exception.Message
                continue
            }

            if ($probe -and -not $probe.Ok) {
                New-AzLocalRemediationResult -Control $control -RunContext $runContext -Outcome 'Failed' `
                    -Message $probe.Message
                continue
            }

            if ($control.RequiresReboot) { $rebootPending.Add($control.Id) }

            New-AzLocalRemediationResult -Control $control -RunContext $runContext -Outcome 'Remediated' `
                -Message $(if ($control.RequiresReboot) {
                    'Applied. A reboot is required before this takes effect.'
                } else {
                    'Applied.'
                })
        }

        if ($rebootPending.Count -gt 0) {
            Write-AzLocalLog -Level Warning -Message ("A reboot is required for: {0}. Drain and reboot one node at a time, confirming cluster health between nodes." -f ($rebootPending -join ', '))
        }
    }
}

function New-AzLocalRemediationResult {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] $Control,
        [Parameter(Mandatory)] $RunContext,
        [Parameter(Mandatory)]
        [ValidateSet('Remediated', 'Skipped', 'Failed', 'NotSupported', 'WhatIf')]
        [string] $Outcome,
        [string] $Message
    )

    return [pscustomobject]@{
        PSTypeName     = 'AzLocal.RemediationResult'
        Id             = $Control.Id
        Title          = $Control.Title
        Category       = $Control.Category
        Severity       = $Control.Severity
        Outcome        = $Outcome
        Message        = $Message
        RequiresReboot = $Control.RequiresReboot
        ComputerName   = $RunContext.ComputerName
        Scope          = $RunContext.Scope
        ModuleVersion  = $script:ModuleVersion
        TimestampUtc   = (Get-Date).ToUniversalTime()
    }
}
