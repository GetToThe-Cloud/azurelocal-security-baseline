#requires -Version 5.1

<#
    RemoteWorker.ps1

    This function is loaded into the module and is also available after the
    module has been copied to a remote Azure Local node. The transport layer
    invokes it with a JSON request so the same public functions and control
    registry are used locally and remotely.
#>

function Invoke-AzLocalRemoteWorker {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $RequestJson
    )

    $request = $null
    $workPath = $null
    $configPath = $null

    try {
        $request = $RequestJson | ConvertFrom-Json -ErrorAction Stop
        $workPath = Join-Path ([System.IO.Path]::GetTempPath()) ("azlsb-worker-" + [guid]::NewGuid().ToString('N'))
        New-Item -Path $workPath -ItemType Directory -Force | Out-Null

        if ($request.ConfigJson) {
            $configPath = Join-Path $workPath 'site.json'
            Set-Content -LiteralPath $configPath -Value ([string] $request.ConfigJson) -Encoding UTF8
        }

        $common = @{}
        if ($request.Scope) { $common['Scope'] = [string] $request.Scope }
        if ($configPath) { $common['ConfigPath'] = $configPath }

        switch ([string] $request.Operation) {
            'Test' {
                if ($request.ControlId) { $common['ControlId'] = @($request.ControlId) }
                if ($request.Category) { $common['Category'] = @($request.Category) }
                if ($request.Severity) { $common['Severity'] = @($request.Severity) }
                if ($request.IncludeSkipped) { $common['IncludeSkipped'] = $true }

                $results = @(Test-AzLocalSecurityBaseline @common)
                $payload = [pscustomobject]@{
                    Ok       = $true
                    Operation = 'Test'
                    Results  = $results
                }
            }

            'State' {
                $state = Get-AzLocalSecurityState @common
                $payload = [pscustomobject]@{
                    Ok        = $true
                    Operation = 'State'
                    State     = $state
                }
            }

            'Set' {
                if ($request.ControlId) { $common['ControlId'] = @($request.ControlId) }
                if ($request.AllowReboot) { $common['AllowReboot'] = $true }
                if ($request.AllowMaintenanceWindow) { $common['AllowMaintenanceWindow'] = $true }

                $result = @()
                if ($request.ResultJson) {
                    $result = @(([string] $request.ResultJson) | ConvertFrom-Json -ErrorAction Stop)
                }

                if ($request.WhatIf) {
                    $common['WhatIf'] = $true
                } else {
                    $common['Confirm'] = $false
                }

                $outcome = if ($result.Count -gt 0) {
                    @($result | Set-AzLocalSecurityBaseline @common)
                } else {
                    @(Set-AzLocalSecurityBaseline @common)
                }

                $payload = [pscustomobject]@{
                    Ok        = $true
                    Operation = 'Set'
                    Results   = $outcome
                }
            }

            default {
                throw "Unsupported remote operation '$($request.Operation)'."
            }
        }

        return ($payload | ConvertTo-Json -Depth 30 -Compress)
    }
    catch {
        $errorPayload = [pscustomobject]@{
            Ok            = $false
            Operation     = if ($request) { [string] $request.Operation } else { $null }
            ErrorType     = $_.Exception.GetType().FullName
            ErrorMessage  = $_.Exception.Message
        }

        return ($errorPayload | ConvertTo-Json -Depth 8 -Compress)
    }
    finally {
        if ($workPath) { Remove-Item -LiteralPath $workPath -Recurse -Force -ErrorAction SilentlyContinue }
    }
}
