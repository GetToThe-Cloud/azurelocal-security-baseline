#requires -Version 5.1

function Test-AzLocalSecurityBaseline {
    <#
        .SYNOPSIS
            Audits an Azure Local system against a security baseline. Read-only.

        .DESCRIPTION
            Evaluates every enabled control in the registry and emits one result
            object per control. Nothing is changed. This is the function to run
            first, on a schedule, and before any remediation.

            Statuses:

              Compliant     the observed state matches the desired state
              NonCompliant  it does not
              Unknown       the state could not be read. A missing cmdlet, a
                            CredSSP refusal or an unreachable node lands here and
                            is never quietly counted as a pass
              NotApplicable the control does not apply to this system
              Skipped       the control is disabled in the configuration

        .PARAMETER ConfigPath
            Path to a JSON configuration file. Values are merged over the shipped
            default profile, so a site file only needs to contain what it changes.

        .PARAMETER Scope
            Local    evaluate this node only. No CredSSP required.
            Cluster  evaluate the value held by the orchestrator.
            AllNodes evaluate the computed value across every node. Requires
                     CredSSP or a direct RDP session.

        .PARAMETER ControlId
            Evaluate only these control IDs. Wildcards are supported.

        .PARAMETER Category
            Evaluate only controls in these categories.

        .PARAMETER Severity
            Evaluate only controls at these severities.

        .PARAMETER IncludeSkipped
            Emit a result for controls disabled in the configuration, rather than
            omitting them.

        .EXAMPLE
            Test-AzLocalSecurityBaseline -Scope Cluster

            Audits the whole cluster against the default profile.

        .EXAMPLE
            Test-AzLocalSecurityBaseline -ConfigPath .\contoso.json |
                Where-Object Status -eq 'NonCompliant' |
                Format-Table Id, Severity, Title, Actual

            The shape most people want for a morning check.

        .EXAMPLE
            $results = Test-AzLocalSecurityBaseline -Scope Cluster
            New-AzLocalSecurityReport -Result $results -Path .\baseline.html

        .OUTPUTS
            AzLocal.ControlResult
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [string] $ConfigPath,

        [ValidateSet('Local', 'Cluster', 'AllNodes')]
        [string] $Scope = 'Local',

        [string[]] $ControlId,

        [string[]] $Category,

        [ValidateSet('Critical', 'High', 'Medium', 'Low')]
        [string[]] $Severity,

        [switch] $IncludeSkipped
    )

    begin {
        $config = Import-AzLocalBaselineConfig -Path $ConfigPath
        $runContext = Get-AzLocalRunContext -Config $config -Scope $Scope -ConfigPath $ConfigPath

        Write-AzLocalLog -Message "Auditing profile '$($runContext.Profile)' at scope '$Scope' on $($runContext.ComputerName)."
    }

    process {
        $controls = Get-AzLocalControlRegistry

        if ($ControlId) {
            $controls = @($controls | Where-Object {
                $control = $_
                @($ControlId | Where-Object { $control.Id -like $_ }).Count -gt 0
            })
        }
        if ($Category) { $controls = @($controls | Where-Object { $Category -contains $_.Category }) }
        if ($Severity) { $controls = @($controls | Where-Object { $Severity -contains $_.Severity }) }

        if ($controls.Count -eq 0) {
            Write-AzLocalLog -Level Warning -Message 'No controls matched the supplied filters.'
            return
        }

        $index = 0
        foreach ($control in $controls) {
            $index++
            $percent = [int](($index / $controls.Count) * 100)
            Write-Progress -Activity 'Auditing Azure Local security baseline' `
                -Status "$($control.Id): $($control.Title)" -PercentComplete $percent

            $setting = Get-AzLocalControlSetting -Config $config -ControlId $control.Id

            if (-not $setting.Enabled) {
                Write-AzLocalLog -Level Debug -Message "$($control.Id) is disabled in the configuration."
                if ($IncludeSkipped) {
                    New-AzLocalControlResult -Control $control -RunContext $runContext -Status 'Skipped' `
                        -Detail 'Disabled in the baseline configuration.'
                }
                continue
            }

            $controlContext = @{
                Config     = $config
                Scope      = $Scope
                Parameters = $setting.Parameters
                Data       = $control.Data
            }

            $check = $null
            try {
                $check = & $control.Test $controlContext
            }
            catch {
                # A control that throws is a bug in the control, not a pass.
                Write-AzLocalLog -Level Warning -Message "$($control.Id) threw during evaluation: $($_.Exception.Message)"
                $check = New-AzLocalCheckResult -Status Unknown `
                    -Detail "The control threw during evaluation: $($_.Exception.Message)"
            }

            if (-not $check) {
                $check = New-AzLocalCheckResult -Status Unknown -Detail 'The control returned no result.'
            }

            New-AzLocalControlResult -Control $control -RunContext $runContext -Status $check.Status `
                -Expected $check.Expected -Actual $check.Actual -Detail $check.Detail -Evidence $check.Evidence
        }

        Write-Progress -Activity 'Auditing Azure Local security baseline' -Completed
    }
}

function New-AzLocalControlResult {
    <#
        .SYNOPSIS
            Combines a control definition and a check result into the object the
            module emits and reports on.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] $Control,
        [Parameter(Mandatory)] $RunContext,
        [Parameter(Mandatory)] [string] $Status,
        $Expected,
        $Actual,
        [string] $Detail,
        [hashtable] $Evidence = @{}
    )

    return [pscustomobject]@{
        PSTypeName                = 'AzLocal.ControlResult'
        Id                        = $Control.Id
        Title                     = $Control.Title
        Category                  = $Control.Category
        Severity                  = $Control.Severity
        Status                    = $Status
        Expected                  = $Expected
        Actual                    = $Actual
        Detail                    = $Detail
        Rationale                 = $Control.Rationale
        Reference                 = $Control.Reference
        Remediable                = $Control.Remediable
        RequiresReboot            = $Control.RequiresReboot
        RequiresMaintenanceWindow = $Control.RequiresMaintenanceWindow
        Evidence                  = $Evidence
        ComputerName              = $RunContext.ComputerName
        Scope                     = $RunContext.Scope
        Profile                   = $RunContext.Profile
        TimestampUtc              = $RunContext.TimestampUtc
    }
}
