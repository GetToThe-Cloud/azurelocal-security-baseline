#requires -Version 5.1
<#
    Helpers.ps1

    Logging, configuration loading and the result object shapes shared by every
    public function in the module.
#>

$script:AzLocalLogLevels = @{ Debug = 0; Info = 1; Warning = 2; Error = 3 }

function Write-AzLocalLog {
    <#
        .SYNOPSIS
            Writes a levelled log line to the appropriate PowerShell stream.

        .DESCRIPTION
            Info goes to the information stream rather than to the host, so that a
            scheduled run can capture it with 6>&1 without polluting the object
            output on the success stream.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Message,

        [ValidateSet('Debug', 'Info', 'Warning', 'Error')]
        [string] $Level = 'Info'
    )

    $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line = "[$stamp] [$($Level.ToUpperInvariant())] $Message"

    switch ($Level) {
        'Debug'   { Write-Debug       $line }
        'Info'    { Write-Information $line -InformationAction Continue }
        'Warning' { Write-Warning     $Message }
        'Error'   { Write-Error       $Message -ErrorAction Continue }
    }
}

function Get-AzLocalDefaultConfigPath {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    return (Join-Path -Path $script:ModuleRoot -ChildPath 'Config/baseline.default.json')
}

function Import-AzLocalBaselineConfig {
    <#
        .SYNOPSIS
            Loads a desired-state configuration file and merges it over the
            shipped default.

        .DESCRIPTION
            A caller's file only has to contain what it changes. Anything absent
            falls back to the default profile, so a site config can be four lines
            long and still be complete.

        .PARAMETER Path
            Path to a JSON configuration file. Omit for the shipped default.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [string] $Path
    )

    $defaultPath = Get-AzLocalDefaultConfigPath
    if (-not (Test-Path -LiteralPath $defaultPath)) {
        throw "The default baseline configuration is missing from the module at '$defaultPath'."
    }

    $config = ConvertFrom-AzLocalJsonFile -Path $defaultPath

    if ($Path) {
        if (-not (Test-Path -LiteralPath $Path)) {
            throw "Baseline configuration file not found: '$Path'."
        }

        $override = ConvertFrom-AzLocalJsonFile -Path $Path
        $config = Merge-AzLocalHashtable -Base $config -Override $override
        Write-AzLocalLog -Level Debug -Message "Merged overrides from '$Path'."
    }

    return $config
}

function ConvertFrom-AzLocalJsonFile {
    <#
        .SYNOPSIS
            Reads a JSON file into nested hashtables.

        .DESCRIPTION
            -AsHashtable is not available on Windows PowerShell 5.1, which is what
            ships on the Azure Local hosts, so PSCustomObject output is converted
            recursively instead.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop

    try {
        $object = $raw | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "'$Path' is not valid JSON: $($_.Exception.Message)"
    }

    return (ConvertTo-AzLocalHashtable -InputObject $object)
}

function ConvertTo-AzLocalHashtable {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        $InputObject
    )

    process {
        if ($null -eq $InputObject) { return $null }

        # PSCustomObject first: it is not IEnumerable, but testing it explicitly
        # keeps the intent obvious and avoids touching .PSObject on value types.
        if ($InputObject -is [System.Management.Automation.PSCustomObject]) {
            $hash = @{}
            foreach ($property in $InputObject.PSObject.Properties) {
                $hash[$property.Name] = ConvertTo-AzLocalHashtable -InputObject $property.Value
            }
            return $hash
        }

        if ($InputObject -is [hashtable]) { return $InputObject }

        if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
            $list = @()
            foreach ($item in $InputObject) {
                $list += ,(ConvertTo-AzLocalHashtable -InputObject $item)
            }
            return ,$list
        }

        return $InputObject
    }
}

function Merge-AzLocalHashtable {
    <#
        .SYNOPSIS
            Deep-merges Override onto a copy of Base. Override wins on conflict.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Base,

        [Parameter(Mandatory)]
        [hashtable] $Override
    )

    $result = @{}
    foreach ($key in $Base.Keys) { $result[$key] = $Base[$key] }

    foreach ($key in $Override.Keys) {
        if ($result.ContainsKey($key) -and $result[$key] -is [hashtable] -and $Override[$key] -is [hashtable]) {
            $result[$key] = Merge-AzLocalHashtable -Base $result[$key] -Override $Override[$key]
        }
        else {
            $result[$key] = $Override[$key]
        }
    }

    return $result
}

function Get-AzLocalControlSetting {
    <#
        .SYNOPSIS
            Reads a control's configuration entry, with defaults applied.

        .OUTPUTS
            A hashtable with at least Enabled (bool) and Parameters (hashtable).
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Config,

        [Parameter(Mandatory)]
        [string] $ControlId
    )

    $entry = $null
    if ($Config.ContainsKey('controls') -and $Config.controls -is [hashtable] -and $Config.controls.ContainsKey($ControlId)) {
        $entry = $Config.controls[$ControlId]
    }

    $enabled = $true
    $parameters = @{}

    if ($entry -is [hashtable]) {
        if ($entry.ContainsKey('enabled')) { $enabled = [bool] $entry['enabled'] }
        if ($entry.ContainsKey('parameters') -and $entry['parameters'] -is [hashtable]) {
            $parameters = $entry['parameters']
        }
    }
    elseif ($entry -is [bool]) {
        $enabled = $entry
    }

    return @{ Enabled = $enabled; Parameters = $parameters }
}

function New-AzLocalCheckResult {
    <#
        .SYNOPSIS
            The object a control's Test scriptblock returns.

        .PARAMETER Status
            Compliant     : the observed state matches the desired state
            NonCompliant  : it does not
            Unknown       : the state could not be read (missing cmdlet, CredSSP,
                            an unreachable node). Never silently treated as a pass.
            NotApplicable : the control does not apply to this system
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Compliant', 'NonCompliant', 'Unknown', 'NotApplicable')]
        [string] $Status,

        $Expected,
        $Actual,
        [string] $Detail,
        [hashtable] $Evidence = @{}
    )

    return [pscustomobject]@{
        PSTypeName = 'AzLocal.CheckResult'
        Status     = $Status
        Expected   = $Expected
        Actual     = $Actual
        Detail     = $Detail
        Evidence   = $Evidence
    }
}

function ConvertTo-AzLocalDisplayValue {
    <#
        .SYNOPSIS
            Renders a value for a report cell without throwing on $null or objects.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        $Value
    )

    if ($null -eq $Value) { return 'not set' }
    if ($Value -is [bool]) { return $(if ($Value) { 'enabled' } else { 'disabled' }) }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        return (($Value | ForEach-Object { ConvertTo-AzLocalDisplayValue -Value $_ }) -join ', ')
    }

    return [string] $Value
}

function Get-AzLocalRunContext {
    <#
        .SYNOPSIS
            Metadata stamped onto every result set, so a report can be traced back
            to who ran it, where and against which configuration.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [hashtable] $Config,
        [string] $Scope,
        [string] $ConfigPath
    )

    $profileName = 'unknown'
    $configVersion = 'unknown'
    if ($Config) {
        if ($Config.ContainsKey('profile')) { $profileName = [string] $Config['profile'] }
        if ($Config.ContainsKey('version')) { $configVersion = [string] $Config['version'] }
    }

    return [pscustomobject]@{
        PSTypeName    = 'AzLocal.RunContext'
        TimestampUtc  = (Get-Date).ToUniversalTime()
        ComputerName  = $env:COMPUTERNAME
        UserName      = "$env:USERDOMAIN\$env:USERNAME"
        Scope         = $Scope
        Profile       = $profileName
        ConfigVersion = $configVersion
        ConfigPath    = $ConfigPath
        ModuleVersion = $script:ModuleVersion
    }
}
