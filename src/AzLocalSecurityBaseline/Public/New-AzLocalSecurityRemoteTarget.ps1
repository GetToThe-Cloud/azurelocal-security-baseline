#requires -Version 5.1

function New-AzLocalSecurityRemoteTarget {
    <#
        .SYNOPSIS
            Creates a target for executing the security baseline remotely.

        .DESCRIPTION
            WinRM is the full-fidelity transport and supports Local, Cluster and
            AllNodes when the target session has the required delegation. Arc Run
            Command runs on an Arc-enabled node without inbound WinRM or RDP and
            intentionally supports Local scope only.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('WinRM', 'ArcRunCommand')]
        [string] $Transport,

        [string] $ComputerName,
        [object] $Session,
        [pscredential] $Credential,

        [ValidateSet('Default', 'Negotiate', 'Kerberos', 'CredSSP', 'Basic')]
        [string] $Authentication = 'Negotiate',

        [switch] $UseSSL,
        [int] $Port,

        [string] $SubscriptionId,
        [string] $ResourceGroupName,
        [string] $MachineName,
        [Parameter(Mandatory = $false)]
        [string] $Location,
        [pscredential] $RunAsCredential,
        [string] $OutputBlobUri,
        [string] $ErrorBlobUri,
        [ValidateRange(30, 7200)]
        [int] $TimeoutInSeconds = 3600,
        [ValidateRange(1, 60)]
        [int] $PollSeconds = 5,
        [switch] $KeepRunCommand
    )

    if ($Transport -eq 'WinRM') {
        if (-not $ComputerName -and -not $Session) {
            throw 'WinRM targets require -ComputerName or an existing -Session.'
        }
        if ($Session -and $Session.PSObject.Properties['State'] -and $Session.State -ne 'Opened') {
            throw "The supplied PSSession is not open: $($Session.State)."
        }
        if ($Authentication -eq 'CredSSP' -and -not $Credential -and -not $Session) {
            throw 'CredSSP targets require -Credential or an existing delegated -Session.'
        }
        if ($Port -eq 0) { $Port = if ($UseSSL) { 5986 } else { 5985 } }

        return [pscustomobject]@{
            PSTypeName     = 'AzLocal.RemoteTarget'
            Transport      = 'WinRM'
            ComputerName   = $ComputerName
            Session        = $Session
            Credential     = $Credential
            Authentication = $Authentication
            UseSSL         = [bool] $UseSSL
            Port           = $Port
        }
    }

    foreach ($name in @('SubscriptionId', 'ResourceGroupName', 'MachineName', 'Location')) {
        if (-not (Get-Variable -Name $name -ValueOnly)) {
            throw "ArcRunCommand targets require -$name."
        }
    }

    return [pscustomobject]@{
        PSTypeName          = 'AzLocal.RemoteTarget'
        Transport           = 'ArcRunCommand'
        SubscriptionId      = $SubscriptionId
        ResourceGroupName   = $ResourceGroupName
        MachineName         = $MachineName
        Location             = $Location
        RunAsCredential      = $RunAsCredential
        # Keep SAS material encrypted in the target object. It is unwrapped only
        # at the final Arc cmdlet call and is never part of a request or result.
        OutputBlobUri       = Protect-AzLocalRemoteSecret -Value $OutputBlobUri
        ErrorBlobUri        = Protect-AzLocalRemoteSecret -Value $ErrorBlobUri
        TimeoutInSeconds    = $TimeoutInSeconds
        PollSeconds         = $PollSeconds
        KeepRunCommand      = [bool] $KeepRunCommand
    }
}
