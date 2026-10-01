#requires -Version 5.1

<#
    Remote.ps1

    The public functions keep their original local contract and delegate to
    this file only when a remote target is supplied. The remote worker is the
    same module code after it has been copied to the target node.
#>

function Get-AzLocalRemoteTargetLabel {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] $Target
    )

    if ($Target.Transport -eq 'WinRM') {
        if ($Target.ComputerName) { return [string] $Target.ComputerName }
        if ($Target.Session -and $Target.Session.ComputerName) { return [string] $Target.Session.ComputerName }
        return 'WinRM target'
    }

    return [string] $Target.MachineName
}

function Protect-AzLocalRemoteSecret {
    [CmdletBinding()]
    [OutputType([System.Security.SecureString])]
    param(
        [string] $Value
    )

    if ([string]::IsNullOrEmpty($Value)) { return $null }
    $secure = New-Object System.Security.SecureString
    foreach ($character in $Value.ToCharArray()) { $secure.AppendChar($character) }
    $secure.MakeReadOnly()
    return $secure
}

function Unprotect-AzLocalRemoteSecret {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [System.Security.SecureString] $Value
    )

    if ($null -eq $Value) { return $null }
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }
}

function ConvertTo-AzLocalRemoteRequest {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Test', 'State', 'Set')]
        [string] $Operation,

        [Parameter(Mandatory)]
        [string] $Scope,

        [string] $ConfigPath,
        [string[]] $ControlId,
        [string[]] $Category,
        [string[]] $Severity,
        [switch] $IncludeSkipped,
        [switch] $AllowReboot,
        [switch] $AllowMaintenanceWindow,
        [switch] $Simulate,
        [psobject[]] $Result
    )

    $request = [ordered]@{
        Operation              = $Operation
        Scope                  = $Scope
        IncludeSkipped         = [bool] $IncludeSkipped
        AllowReboot            = [bool] $AllowReboot
        AllowMaintenanceWindow = [bool] $AllowMaintenanceWindow
        WhatIf                 = [bool] $Simulate
    }

    if ($ConfigPath) {
        if (-not (Test-Path -LiteralPath $ConfigPath)) {
            throw "Baseline configuration file not found: '$ConfigPath'."
        }
        $request['ConfigJson'] = Get-Content -LiteralPath $ConfigPath -Raw -ErrorAction Stop
    }

    if ($ControlId) { $request['ControlId'] = @($ControlId) }
    if ($Category) { $request['Category'] = @($Category) }
    if ($Severity) { $request['Severity'] = @($Severity) }
    if ($Result -and @($Result).Count -gt 0) {
        # Remediation needs only finding fields. Do not forward Evidence or any
        # arbitrary properties that could contain recovery keys or credentials.
        $safeResults = foreach ($item in @($Result)) {
            [ordered]@{
                Id       = $item.Id
                Status   = $item.Status
                Expected = $item.Expected
                Actual   = $item.Actual
                Detail   = $item.Detail
            }
        }
        $request['ResultJson'] = @($safeResults) | ConvertTo-Json -Depth 12 -Compress
    }

    return ($request | ConvertTo-Json -Depth 25 -Compress)
}

function Add-AzLocalRemoteResultProperty {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Value,
        [Parameter(Mandatory)] $Target,
        [Parameter(Mandatory)] [string] $Operation,
        [Parameter(Mandatory)] [string] $ExecutionId
    )

    $properties = [ordered]@{}
    if ($Value -and $Value.PSObject) {
        foreach ($property in $Value.PSObject.Properties) {
            $properties[$property.Name] = $property.Value
        }
    }

    $properties['Transport'] = [string] $Target.Transport
    $properties['TargetComputerName'] = Get-AzLocalRemoteTargetLabel -Target $Target
    $properties['ExecutionId'] = $ExecutionId
    $properties['RemoteOperation'] = $Operation
    $properties['ModuleVersion'] = [string] $script:ModuleVersion

    return [pscustomobject] $properties
}

function Get-AzLocalRemoteUnknownResult {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $Scope,

        [string] $ConfigPath,
        [switch] $IncludeSkipped,
        [Parameter(Mandatory)]
        [string] $Message,

        [Parameter(Mandatory)] $Target,
        [Parameter(Mandatory)] [string] $ExecutionId
    )

    $config = Import-AzLocalBaselineConfig -Path $ConfigPath
    $profileName = if ($config.ContainsKey('profile')) { [string] $config.profile } else { 'unknown' }
    $timestamp = (Get-Date).ToUniversalTime()

    foreach ($control in (Get-AzLocalControlRegistry)) {
        $setting = Get-AzLocalControlSetting -Config $config -ControlId $control.Id
        if (-not $setting.Enabled -and -not $IncludeSkipped) { continue }

        [pscustomobject]@{
            PSTypeName                = 'AzLocal.ControlResult'
            Id                        = $control.Id
            Title                     = $control.Title
            Category                  = $control.Category
            Severity                  = $control.Severity
            Status                    = if ($setting.Enabled) { 'Unknown' } else { 'Skipped' }
            Expected                  = $null
            Actual                    = $null
            Detail                    = if ($setting.Enabled) { "Remote execution failed: $Message" } else { 'Disabled in the baseline configuration.' }
            Rationale                 = $control.Rationale
            Reference                 = $control.Reference
            Remediable                = $control.Remediable
            RequiresReboot            = $control.RequiresReboot
            RequiresMaintenanceWindow = $control.RequiresMaintenanceWindow
            Evidence                  = @{ TransportError = if ($setting.Enabled) { $Message } else { $null } }
            ComputerName              = Get-AzLocalRemoteTargetLabel -Target $Target
            Scope                     = $Scope
            Profile                   = $profileName
            TimestampUtc              = $timestamp
            Transport                 = [string] $Target.Transport
            TargetComputerName        = Get-AzLocalRemoteTargetLabel -Target $Target
            ExecutionId               = $ExecutionId
            RemoteOperation           = 'Test'
            ModuleVersion             = [string] $script:ModuleVersion
        }
    }
}

function Invoke-AzLocalRemoteOperation {
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Test', 'State', 'Set')]
        [string] $Operation,

        [Parameter(Mandatory)] $Target,
        [Parameter(Mandatory)] [string] $Scope,
        [string] $ConfigPath,
        [string[]] $ControlId,
        [string[]] $Category,
        [string[]] $Severity,
        [switch] $IncludeSkipped,
        [switch] $AllowReboot,
        [switch] $AllowMaintenanceWindow,
        [switch] $Simulate,
        [psobject[]] $Result
    )

    if ($Target.Transport -eq 'ArcRunCommand' -and $Scope -ne 'Local') {
        throw "Arc Run Command supports only -Scope Local. Use WinRM with CredSSP for '$Scope'."
    }

    if ($Target.Transport -eq 'WinRM' -and $Scope -in @('Cluster', 'AllNodes')) {
        if (-not $Target.Session -and $Target.Authentication -ne 'CredSSP') {
            throw "Scope '$Scope' requires a CredSSP WinRM target or an existing delegated PSSession."
        }
    }

    $executionId = [guid]::NewGuid().ToString('N')
    $requestJson = ConvertTo-AzLocalRemoteRequest `
        -Operation $Operation `
        -Scope $Scope `
        -ConfigPath $ConfigPath `
        -ControlId $ControlId `
        -Category $Category `
        -Severity $Severity `
        -IncludeSkipped:$IncludeSkipped `
        -AllowReboot:$AllowReboot `
        -AllowMaintenanceWindow:$AllowMaintenanceWindow `
        -Simulate:$Simulate `
        -Result $Result

    try {
        $responseJson = if ($Target.Transport -eq 'WinRM') {
            Invoke-AzLocalWinRM -Target $Target -RequestJson $requestJson
        } else {
            Invoke-AzLocalArcRunCommand -Target $Target -RequestJson $requestJson -ExecutionId $executionId
        }

        $response = [string] $responseJson | ConvertFrom-Json -ErrorAction Stop
        if (-not $response.Ok) {
            throw [System.InvalidOperationException]::new([string] $response.ErrorMessage)
        }

        switch ($Operation) {
            'Test' {
                foreach ($item in @($response.Results)) {
                    Add-AzLocalRemoteResultProperty -Value $item -Target $Target -Operation $Operation -ExecutionId $executionId
                }
            }
            'State' {
                Add-AzLocalRemoteResultProperty -Value $response.State -Target $Target -Operation $Operation -ExecutionId $executionId
            }
            'Set' {
                foreach ($item in @($response.Results)) {
                    Add-AzLocalRemoteResultProperty -Value $item -Target $Target -Operation $Operation -ExecutionId $executionId
                }
            }
        }
    }
    catch {
        if ($Operation -eq 'Test') {
            Get-AzLocalRemoteUnknownResult -Scope $Scope -ConfigPath $ConfigPath `
                -IncludeSkipped:$IncludeSkipped -Message $_.Exception.Message -Target $Target -ExecutionId $executionId
            return
        }

        throw "Remote $Operation on '$(Get-AzLocalRemoteTargetLabel -Target $Target)' failed: $($_.Exception.Message)"
    }
}

function Invoke-AzLocalWinRM {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] $Target,
        [Parameter(Mandatory)] [string] $RequestJson
    )

    $session = $Target.Session
    $ownedSession = $false
    $localTemp = Join-Path ([System.IO.Path]::GetTempPath()) ("azlsb-remote-" + [guid]::NewGuid().ToString('N'))
    $remoteTemp = Join-Path ([System.IO.Path]::GetTempPath()) ("azlsb-remote-" + [guid]::NewGuid().ToString('N'))

    try {
        New-Item -Path $localTemp -ItemType Directory -Force | Out-Null
        $archivePath = Join-Path $localTemp 'module.zip'
        Compress-Archive -Path (Join-Path $script:ModuleRoot '*') -DestinationPath $archivePath -Force

        if (-not $session) {
            $sessionSplat = @{
                ComputerName = $Target.ComputerName
                Authentication = $Target.Authentication
                UseSSL = [bool] $Target.UseSSL
                Port = [int] $Target.Port
            }
            if ($Target.Credential) { $sessionSplat['Credential'] = $Target.Credential }
            $session = New-PSSession @sessionSplat
            $ownedSession = $true
        }

        Invoke-Command -Session $session -ScriptBlock {
            param($path)
            New-Item -Path $path -ItemType Directory -Force | Out-Null
        } -ArgumentList $remoteTemp | Out-Null

        $remoteArchive = Join-Path $remoteTemp 'module.zip'
        Copy-Item -LiteralPath $archivePath -Destination $remoteArchive -ToSession $session -Force

        $response = Invoke-Command -Session $session -ScriptBlock {
            param($path, $request)
            $modulePath = Join-Path $path 'module'
            Expand-Archive -LiteralPath (Join-Path $path 'module.zip') -DestinationPath $modulePath -Force
            $manifest = Join-Path $modulePath 'AzLocalSecurityBaseline.psd1'
            Import-Module -Name $manifest -Force | Out-Null
            $module = Get-Module -Name AzLocalSecurityBaseline | Select-Object -First 1
            & $module { param($json) Invoke-AzLocalRemoteWorker -RequestJson $json } $request
        } -ArgumentList $remoteTemp, $RequestJson

        return [string] $response[-1]
    }
    finally {
        if ($session) {
            Invoke-Command -Session $session -ScriptBlock {
                param($path)
                Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
            } -ArgumentList $remoteTemp -ErrorAction SilentlyContinue | Out-Null
        }
        if ($ownedSession -and $session) { Remove-PSSession -Session $session -ErrorAction SilentlyContinue }
        Remove-Item -LiteralPath $localTemp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Get-AzLocalArcRunCommandOutput {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] $State,
        [string] $OutputBlobUri
    )

    if ($OutputBlobUri) {
        $download = Invoke-WebRequest -Uri $OutputBlobUri -UseBasicParsing -ErrorAction Stop
        if ($download.Content -is [byte[]]) {
            return [Text.Encoding]::UTF8.GetString($download.Content)
        }
        return [string] $download.Content
    }

    foreach ($property in @('InstanceViewOutput', 'Output', 'OutputText')) {
        $candidate = $State.PSObject.Properties[$property]
        if ($candidate -and $candidate.Value) { return [string] $candidate.Value }
    }

    return $null
}

function Invoke-AzLocalArcRunCommand {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] $Target,
        [Parameter(Mandatory)] [string] $RequestJson,
        [Parameter(Mandatory)] [string] $ExecutionId
    )

    foreach ($command in @('New-AzConnectedMachineRunCommand', 'Get-AzConnectedMachineRunCommand')) {
        if (-not (Get-Command -Name $command -ErrorAction SilentlyContinue)) {
            throw "The Az.ConnectedMachine cmdlet '$command' is required for Arc Run Command."
        }
    }

    $localTemp = Join-Path ([System.IO.Path]::GetTempPath()) ("azlsb-arc-" + $ExecutionId)
    $runCommandName = ('azlsb-' + $ExecutionId.Substring(0, 12))
    $state = $null
    $outputBlobUri = Unprotect-AzLocalRemoteSecret -Value $Target.OutputBlobUri
    $errorBlobUri = Unprotect-AzLocalRemoteSecret -Value $Target.ErrorBlobUri

    try {
        New-Item -Path $localTemp -ItemType Directory -Force | Out-Null
        $archivePath = Join-Path $localTemp 'module.zip'
        Compress-Archive -Path (Join-Path $script:ModuleRoot '*') -DestinationPath $archivePath -Force

        $archiveBase64 = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($archivePath))
        $requestBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($RequestJson))
        $scriptPath = Join-Path $localTemp 'run.ps1'
        $script = @"
`$ErrorActionPreference = 'Stop'
`$work = Join-Path ([System.IO.Path]::GetTempPath()) 'azlsb-arc-worker'
New-Item -Path `$work -ItemType Directory -Force | Out-Null
`$zip = Join-Path `$work 'module.zip'
[System.IO.File]::WriteAllBytes(`$zip, [Convert]::FromBase64String('$archiveBase64'))
`$modulePath = Join-Path `$work 'module'
Expand-Archive -LiteralPath `$zip -DestinationPath `$modulePath -Force
`$request = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$requestBase64'))
Import-Module (Join-Path `$modulePath 'AzLocalSecurityBaseline.psd1') -Force | Out-Null
`$module = Get-Module -Name AzLocalSecurityBaseline | Select-Object -First 1
`$response = & `$module { param(`$json) Invoke-AzLocalRemoteWorker -RequestJson `$json } `$request
[Console]::Out.WriteLine([string] `$response)
Remove-Item -LiteralPath `$work -Recurse -Force -ErrorAction SilentlyContinue
"@
        Set-Content -LiteralPath $scriptPath -Value $script -Encoding UTF8

        $newCommand = Get-Command -Name New-AzConnectedMachineRunCommand
        $runSplat = @{
            ResourceGroupName = $Target.ResourceGroupName
            MachineName       = $Target.MachineName
            Location           = $Target.Location
            RunCommandName    = $runCommandName
            TimeoutInSecond   = [int] $Target.TimeoutInSeconds
        }

        if ($newCommand.Parameters.ContainsKey('SubscriptionId')) {
            $runSplat['SubscriptionId'] = $Target.SubscriptionId
        } elseif (Get-Command -Name Set-AzContext -ErrorAction SilentlyContinue) {
            Set-AzContext -Subscription $Target.SubscriptionId -ErrorAction Stop | Out-Null
        }

        if ($newCommand.Parameters.ContainsKey('ScriptLocalPath')) {
            $runSplat['ScriptLocalPath'] = $scriptPath
        } else {
            $runSplat['SourceScript'] = $script
        }
        if ($outputBlobUri -and $newCommand.Parameters.ContainsKey('OutputBlobUri')) {
            $runSplat['OutputBlobUri'] = $outputBlobUri
        }
        if ($errorBlobUri -and $newCommand.Parameters.ContainsKey('ErrorBlobUri')) {
            $runSplat['ErrorBlobUri'] = $errorBlobUri
        }
        if ($Target.RunAsCredential -and $newCommand.Parameters.ContainsKey('RunAsUser')) {
            $runSplat['RunAsUser'] = $Target.RunAsCredential.UserName
            $runSplat['RunAsPassword'] = $Target.RunAsCredential.GetNetworkCredential().Password
        }
        if ($newCommand.Parameters.ContainsKey('AsyncExecution')) { $runSplat['AsyncExecution'] = $false }

        New-AzConnectedMachineRunCommand @runSplat | Out-Null

        $deadline = (Get-Date).ToUniversalTime().AddSeconds([int] $Target.TimeoutInSeconds + 60)
        $getCommand = Get-Command -Name Get-AzConnectedMachineRunCommand
        $getSplat = @{
            ResourceGroupName = $Target.ResourceGroupName
            MachineName       = $Target.MachineName
            RunCommandName    = $runCommandName
        }
        if ($getCommand.Parameters.ContainsKey('SubscriptionId')) {
            $getSplat['SubscriptionId'] = $Target.SubscriptionId
        }

        do {
            $state = Get-AzConnectedMachineRunCommand @getSplat

            $executionState = $null
            foreach ($property in @('InstanceViewExecutionState', 'ExecutionState', 'ProvisioningState')) {
                $candidate = $state.PSObject.Properties[$property]
                if ($candidate -and $candidate.Value) { $executionState = [string] $candidate.Value; break }
            }

            if ($executionState -eq 'Succeeded') { break }
            if ($executionState -match '^(Failed|TimedOut|Canceled|Cancelled|Expired)$') {
                $errorProperty = $state.PSObject.Properties['InstanceViewError']
                $errorMessage = if ($errorProperty -and $errorProperty.Value) { [string] $errorProperty.Value } else { "Execution state: $executionState" }
                throw "Arc Run Command '$runCommandName' failed: $errorMessage"
            }
            if ((Get-Date).ToUniversalTime() -ge $deadline) { throw "Arc Run Command '$runCommandName' timed out." }
            Start-Sleep -Seconds ([int] $Target.PollSeconds)
        } while ($true)

        $output = Get-AzLocalArcRunCommandOutput -State $state -OutputBlobUri $outputBlobUri
        if (-not $output) { throw 'Arc Run Command returned no output. Supply a unique OutputBlobUri for structured results.' }
        return $output
    }
    finally {
        if (-not $Target.KeepRunCommand) {
            $removeCommand = Get-Command -Name Remove-AzConnectedMachineRunCommand -ErrorAction SilentlyContinue
            if ($removeCommand) {
                $removeSplat = @{
                    ResourceGroupName = $Target.ResourceGroupName
                    MachineName       = $Target.MachineName
                    RunCommandName    = $runCommandName
                    ErrorAction       = 'SilentlyContinue'
                }
                if ($removeCommand.Parameters.ContainsKey('SubscriptionId')) {
                    $removeSplat['SubscriptionId'] = $Target.SubscriptionId
                }
                if ($removeCommand.Parameters.ContainsKey('Force')) {
                    $removeSplat['Force'] = $true
                } elseif ($removeCommand.Parameters.ContainsKey('Confirm')) {
                    $removeSplat['Confirm'] = $false
                }
                Remove-AzConnectedMachineRunCommand @removeSplat
            }
        }
        $outputBlobUri = $null
        $errorBlobUri = $null
        Remove-Item -LiteralPath $localTemp -Recurse -Force -ErrorAction SilentlyContinue
    }
}
