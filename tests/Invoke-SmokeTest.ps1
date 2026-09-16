#requires -Version 5.1
<#
    .SYNOPSIS
        Dependency-free verification of AzLocalSecurityBaseline.

    .DESCRIPTION
        The full suite in AzLocalSecurityBaseline.Tests.ps1 needs Pester 5. This
        script covers the same critical behaviour with no dependencies at all, by
        injecting stub functions directly into the module's session state, so it
        runs on a locked-down jump box or an air-gapped build agent.

        It never touches the machine it runs on: every interop function, read and
        write alike, is stubbed.

    .EXAMPLE
        pwsh -File ./tests/Invoke-SmokeTest.ps1

    .OUTPUTS
        Exit code 0 when every assertion passes, 1 otherwise.
#>
[CmdletBinding()]
param(
    [string] $ModulePath = (Join-Path $PSScriptRoot '../src/AzLocalSecurityBaseline/AzLocalSecurityBaseline.psd1')
)

$ErrorActionPreference = 'Stop'

$script:Passed = 0
$script:Failed = 0

function Test-Case {
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [scriptblock] $Body
    )

    try {
        & $Body
        $script:Passed++
        Write-Host "  PASS  $Name" -ForegroundColor Green
    }
    catch {
        $script:Failed++
        Write-Host "  FAIL  $Name" -ForegroundColor Red
        Write-Host "        $($_.Exception.Message)" -ForegroundColor DarkGray
    }
}

function Assert-Equal {
    param($Expected, $Actual, [string] $Because = '')

    $expectedText = if ($null -eq $Expected) { '<null>' } else { [string] $Expected }
    $actualText = if ($null -eq $Actual) { '<null>' } else { [string] $Actual }

    if ($expectedText -ne $actualText) {
        throw "Expected '$expectedText' but got '$actualText'. $Because"
    }
}

function Assert-Match {
    param([string] $Pattern, $Actual, [string] $Because = '')

    if (([string] $Actual) -notmatch $Pattern) {
        throw "Expected a value matching '$Pattern' but got '$Actual'. $Because"
    }
}

function Assert-True {
    param($Condition, [string] $Because = '')
    if (-not $Condition) { throw "Expected a true condition. $Because" }
}

Import-Module $ModulePath -Force
$module = Get-Module AzLocalSecurityBaseline

<#
    Installs a complete set of stubs representing a healthy cluster into the
    module's session state, plus counters so a test can assert that no write path
    was called. Call this before each test to reset.
#>
function Reset-Stub {
    & $module {
        $script:WriteCalls = @{}

        function script:Record-Write { param([string] $Name)
            if (-not $script:WriteCalls.ContainsKey($Name)) { $script:WriteCalls[$Name] = 0 }
            $script:WriteCalls[$Name]++
        }

        function script:Ok { param($Value) [pscustomobject]@{ Ok = $true; Value = $Value; Reason = $null; Message = $null } }
        function script:Fail { param([string] $Message) [pscustomobject]@{ Ok = $false; Value = $null; Reason = 'MissingCommand'; Message = $Message } }

        # ---- read paths -------------------------------------------------
        function script:Get-AzLocalSecurityFeature { param($FeatureName, $Scope) script:Ok $true }
        function script:Get-AzLocalWdacMode { script:Ok 'Enforced' }
        function script:Get-AzLocalWdacPolicyInventory {
            script:Ok @([pscustomobject]@{ PolicyName = 'AS_Base_Policy'; IsSystemPolicy = $true })
        }
        function script:Get-AzLocalBitLockerVolume { param($VolumeType, $Scope)
            script:Ok @([pscustomobject]@{ MountPoint = 'C:'; ProtectionStatus = 'On' })
        }
        function script:Get-AzLocalBitLockerRecoveryKey {
            script:Ok @([pscustomobject]@{ ComputerName = 'NODE01'; PasswordID = 'p1'; RecoveryKey = 'TOPSECRETKEYMATERIAL' })
        }
        function script:Get-AzLocalSyslogForwarder { param($Scope)
            script:Ok ([pscustomobject]@{
                ServerName = 'siem.contoso.local'; UseUDP = $false; NoEncryption = $false
                SkipServerCertificateCheck = $false; SkipServerCNCheck = $false
                ClientCertificateThumbprint = 'AABBCC'
            })
        }
        function script:Get-AzLocalDefenderStatus {
            script:Ok ([pscustomobject]@{ RealTimeProtectionEnabled = $true; AMServiceEnabled = $true; AntivirusSignatureAge = 1 })
        }
        function script:Get-AzLocalDefenderPreference { script:Ok ([pscustomobject]@{ PUAProtection = 1 }) }
        function script:Get-AzLocalTpm { script:Ok ([pscustomobject]@{ TpmPresent = $true; TpmReady = $true }) }
        function script:Get-AzLocalSecureBootState { script:Ok $true }
        function script:Get-AzLocalSolutionUpdateEnvironment {
            script:Ok ([pscustomobject]@{ HealthState = 'Success'; CurrentVersion = '12.2608.1003.9' })
        }
        function script:Get-AzLocalPasswordPolicy { script:Ok ([pscustomobject]@{ MinimumPasswordLength = 14 }) }
        function script:Get-AzLocalLocalUser {
            script:Ok @(
                [pscustomobject]@{ Name = 'ASBuiltInAdmin'; Enabled = $false; Rid = 500 }
                [pscustomobject]@{ Name = 'ASBuiltInGuest'; Enabled = $false; Rid = 501 }
            )
        }
        function script:Get-AzLocalRegistryValue { param($Path, $Name) script:Ok 'Authorised use only' }

        # ---- write paths ------------------------------------------------
        function script:Set-AzLocalSecurityFeature { param($FeatureName, $Enabled, $Scope)
            script:Record-Write 'Set-AzLocalSecurityFeature'; script:Ok $null }
        function script:Set-AzLocalWdacMode { param($Mode)
            script:Record-Write "Set-AzLocalWdacMode:$Mode"; script:Ok $null }
        function script:Enable-AzLocalBitLockerVolume { param($VolumeType, $MountPoint, $Scope)
            script:Record-Write 'Enable-AzLocalBitLockerVolume'; script:Ok $null }
        function script:Set-AzLocalRegistryValue { param($Path, $Name, $Value)
            script:Record-Write 'Set-AzLocalRegistryValue'; script:Ok $null }
        function script:Set-AzLocalPasswordPolicyLength { param($MinimumLength)
            script:Record-Write 'Set-AzLocalPasswordPolicyLength'; script:Ok $null }
    }
}

function Get-WriteCount {
    param([string] $Name)
    $calls = & $module { $script:WriteCalls }
    if ($Name) {
        if ($calls.ContainsKey($Name)) { return $calls[$Name] }
        return 0
    }
    $total = 0
    foreach ($value in $calls.Values) { $total += $value }
    return $total
}

function Set-Stub {
    param([Parameter(Mandatory)] [scriptblock] $Definition)
    & $module $Definition
}

$temp = Join-Path ([System.IO.Path]::GetTempPath()) ("azlsb-" + [guid]::NewGuid().ToString('N'))
New-Item -Path $temp -ItemType Directory -Force | Out-Null

try {
    Write-Host ''
    Write-Host 'Module surface' -ForegroundColor Cyan

    Test-Case 'exports exactly four functions' {
        $exported = ($module.ExportedFunctions.Keys | Sort-Object) -join ','
        Assert-Equal 'Get-AzLocalSecurityState,New-AzLocalSecurityReport,Set-AzLocalSecurityBaseline,Test-AzLocalSecurityBaseline' $exported
    }

    Test-Case 'manifest FunctionsToExport matches the module' {
        $manifest = Import-PowerShellDataFile -Path $ModulePath
        Assert-Equal (($manifest.FunctionsToExport | Sort-Object) -join ',') (($module.ExportedFunctions.Keys | Sort-Object) -join ',')
    }

    Test-Case 'only the Set function supports -WhatIf' {
        Assert-True (-not (Get-Command Test-AzLocalSecurityBaseline).Parameters.ContainsKey('WhatIf')) 'Test should be read-only'
        Assert-True ((Get-Command Set-AzLocalSecurityBaseline).Parameters.ContainsKey('WhatIf')) 'Set should support WhatIf'
    }

    Write-Host ''
    Write-Host 'Control registry' -ForegroundColor Cyan

    Test-Case 'control IDs are unique' {
        $duplicates = & $module { (Get-AzLocalControlRegistry) | Group-Object Id | Where-Object Count -gt 1 }
        Assert-Equal 0 (@($duplicates).Count)
    }

    Test-Case 'every control has a rationale and a Learn reference' {
        $bad = & $module {
            (Get-AzLocalControlRegistry) | Where-Object {
                [string]::IsNullOrWhiteSpace($_.Rationale) -or $_.Reference -notmatch '^https://learn\.microsoft\.com/'
            }
        }
        Assert-Equal 0 (@($bad).Count) "Offenders: $((@($bad).Id) -join ', ')"
    }

    Test-Case 'default config covers every control and no phantom controls' {
        $result = & $module {
            $config = Import-AzLocalBaselineConfig
            $ids = (Get-AzLocalControlRegistry).Id
            [pscustomobject]@{
                Missing = @($ids | Where-Object { -not $config.controls.ContainsKey($_) })
                Phantom = @($config.controls.Keys | Where-Object { $ids -notcontains $_ })
            }
        }
        Assert-Equal 0 $result.Missing.Count "Missing from config: $($result.Missing -join ', ')"
        Assert-Equal 0 $result.Phantom.Count "Phantom entries: $($result.Phantom -join ', ')"
    }

    Write-Host ''
    Write-Host 'Audit behaviour' -ForegroundColor Cyan

    Test-Case 'a healthy system reports every control compliant' {
        Reset-Stub
        $results = Test-AzLocalSecurityBaseline -Scope Local
        $notCompliant = @($results | Where-Object Status -ne 'Compliant')
        Assert-True (@($results).Count -gt 20) 'expected the full control set'
        Assert-Equal 0 $notCompliant.Count "Offenders: $(($notCompliant | ForEach-Object { "$($_.Id)=$($_.Status)" }) -join ', ')"
    }

    Test-Case 'an audit never calls a write path' {
        Reset-Stub
        Test-AzLocalSecurityBaseline -Scope Local | Out-Null
        Assert-Equal 0 (Get-WriteCount)
    }

    Test-Case 'Application Control left in audit mode is a critical finding' {
        Reset-Stub
        Set-Stub { function script:Get-AzLocalWdacMode { script:Ok 'Audit' } }
        $result = Test-AzLocalSecurityBaseline -Scope Local -ControlId 'AZL-WDAC-001'
        Assert-Equal 'NonCompliant' $result.Status
        Assert-Equal 'Critical' $result.Severity
    }

    Test-Case 'an unencrypted CSV is named in the finding' {
        Reset-Stub
        Set-Stub {
            function script:Get-AzLocalBitLockerVolume { param($VolumeType, $Scope)
                if ($VolumeType -eq 'ClusterSharedVolume') {
                    return script:Ok @(
                        [pscustomobject]@{ MountPoint = 'C:\ClusterStorage\Volume1'; ProtectionStatus = 'On' }
                        [pscustomobject]@{ MountPoint = 'C:\ClusterStorage\Volume3'; ProtectionStatus = 'Off' }
                    )
                }
                return script:Ok @([pscustomobject]@{ MountPoint = 'C:'; ProtectionStatus = 'On' })
            }
        }
        $result = Test-AzLocalSecurityBaseline -Scope Local -ControlId 'AZL-BL-002'
        Assert-Equal 'NonCompliant' $result.Status
        Assert-Equal '1/2 protected' $result.Actual
        Assert-Match 'Volume3' $result.Detail
    }

    Test-Case 'UDP and unencrypted syslog are both reported' {
        Reset-Stub
        Set-Stub {
            function script:Get-AzLocalSyslogForwarder { param($Scope)
                script:Ok ([pscustomobject]@{
                    ServerName = 'siem.contoso.local'; UseUDP = $true; NoEncryption = $true
                    SkipServerCertificateCheck = $false; SkipServerCNCheck = $false
                    ClientCertificateThumbprint = ''
                })
            }
        }
        $result = Test-AzLocalSecurityBaseline -Scope Local -ControlId 'AZL-LOG-002'
        Assert-Equal 'NonCompliant' $result.Status
        Assert-Match 'UDP transport' $result.Detail
        Assert-Match 'encryption disabled' $result.Detail
    }

    Test-Case 'a missing cmdlet yields Unknown, never Compliant' {
        Reset-Stub
        Set-Stub { function script:Get-AzLocalSecurityFeature { param($FeatureName, $Scope) script:Fail "The cmdlet 'Get-AzsSecurity' is not available." } }
        $result = Test-AzLocalSecurityBaseline -Scope Local -ControlId 'AZL-VBS-001'
        Assert-Equal 'Unknown' $result.Status
        Assert-Match 'not available' $result.Detail
    }

    Test-Case 'a control that throws yields Unknown, never Compliant' {
        Reset-Stub
        Set-Stub { function script:Get-AzLocalTpm { throw 'catastrophic failure' } }
        $result = Test-AzLocalSecurityBaseline -Scope Local -ControlId 'AZL-HW-001' -WarningAction SilentlyContinue
        Assert-Equal 'Unknown' $result.Status
    }

    Test-Case 'a mixed per-node feature result is non-compliant' {
        Reset-Stub
        Set-Stub {
            function script:Get-AzLocalSecurityFeature { param($FeatureName, $Scope)
                script:Ok @([pscustomobject]@{ Value = $true }, [pscustomobject]@{ Value = $false })
            }
        }
        $result = Test-AzLocalSecurityBaseline -Scope AllNodes -ControlId 'AZL-HVCI-001'
        Assert-Equal 'NonCompliant' $result.Status
    }

    Test-Case 'an undocumented supplemental WDAC policy is flagged' {
        Reset-Stub
        Set-Stub {
            function script:Get-AzLocalWdacPolicyInventory {
                script:Ok @(
                    [pscustomobject]@{ PolicyName = 'AS_Base_Policy'; IsSystemPolicy = $true }
                    [pscustomobject]@{ PolicyName = 'MysteryAgent'; IsSystemPolicy = $false }
                )
            }
        }
        $result = Test-AzLocalSecurityBaseline -Scope Local -ControlId 'AZL-WDAC-002'
        Assert-Equal 'NonCompliant' $result.Status
        Assert-Match 'MysteryAgent' $result.Detail
    }

    Test-Case 'an approved-policy allow list makes it compliant' {
        Reset-Stub
        Set-Stub {
            function script:Get-AzLocalWdacPolicyInventory {
                script:Ok @(
                    [pscustomobject]@{ PolicyName = 'AS_Base_Policy'; IsSystemPolicy = $true }
                    [pscustomobject]@{ PolicyName = 'VeeamAgent'; IsSystemPolicy = $false }
                )
            }
        }
        $configPath = Join-Path $temp 'approved.json'
        '{ "controls": { "AZL-WDAC-002": { "parameters": { "approvedPolicies": ["VeeamAgent"] } } } }' |
            Set-Content -LiteralPath $configPath

        $result = Test-AzLocalSecurityBaseline -Scope Local -ControlId 'AZL-WDAC-002' -ConfigPath $configPath
        Assert-Equal 'Compliant' $result.Status
    }

    Test-Case 'a disabled control is omitted, and shown with -IncludeSkipped' {
        Reset-Stub
        $configPath = Join-Path $temp 'disabled.json'
        '{ "controls": { "AZL-SMB-002": { "enabled": false } } }' | Set-Content -LiteralPath $configPath

        $omitted = @(Test-AzLocalSecurityBaseline -Scope Local -ConfigPath $configPath | Where-Object Id -eq 'AZL-SMB-002')
        Assert-Equal 0 $omitted.Count

        $included = @(Test-AzLocalSecurityBaseline -Scope Local -ConfigPath $configPath -IncludeSkipped | Where-Object Id -eq 'AZL-SMB-002')
        Assert-Equal 'Skipped' $included[0].Status
    }

    Test-Case 'wildcard control filtering works' {
        Reset-Stub
        $results = @(Test-AzLocalSecurityBaseline -Scope Local -ControlId 'AZL-BL-*')
        Assert-Equal 3 $results.Count
        Assert-Equal 0 (@($results | Where-Object Category -ne 'Data at rest').Count)
    }

    Test-Case 'recovery key material never reaches a result object' {
        Reset-Stub
        $result = Test-AzLocalSecurityBaseline -Scope Local -ControlId 'AZL-BL-003'
        $json = $result | ConvertTo-Json -Depth 8
        Assert-True ($json -notmatch 'TOPSECRETKEYMATERIAL') 'key material leaked into the result'
        Assert-Equal 'Compliant' $result.Status
    }

    Test-Case 'a custom minimum password length is honoured' {
        Reset-Stub
        $configPath = Join-Path $temp 'pwlen.json'
        '{ "controls": { "AZL-PWD-001": { "parameters": { "minimumLength": 20 } } } }' | Set-Content -LiteralPath $configPath

        $result = Test-AzLocalSecurityBaseline -Scope Local -ControlId 'AZL-PWD-001' -ConfigPath $configPath
        Assert-Equal 'NonCompliant' $result.Status
        Assert-Equal '>= 20' $result.Expected
    }

    Write-Host ''
    Write-Host 'Remediation safety' -ForegroundColor Cyan

    Test-Case 'a compliant system triggers no writes' {
        Reset-Stub
        Set-AzLocalSecurityBaseline -Scope Local -Confirm:$false | Out-Null
        Assert-Equal 0 (Get-WriteCount)
    }

    Test-Case '-WhatIf reports the intent and writes nothing' {
        Reset-Stub
        Set-Stub { function script:Get-AzLocalWdacMode { script:Ok 'Audit' } }
        $outcome = Set-AzLocalSecurityBaseline -Scope Local -ControlId 'AZL-WDAC-001' -WhatIf
        Assert-Equal 'WhatIf' $outcome.Outcome
        Assert-Equal 0 (Get-WriteCount)
    }

    Test-Case 'a confirmed remediation calls the write path exactly once' {
        Reset-Stub
        Set-Stub { function script:Get-AzLocalWdacMode { script:Ok 'Audit' } }
        $outcome = Set-AzLocalSecurityBaseline -Scope Local -ControlId 'AZL-WDAC-001' -Confirm:$false
        Assert-Equal 'Remediated' $outcome.Outcome
        Assert-Equal 1 (Get-WriteCount 'Set-AzLocalWdacMode:Enforced')
    }

    Test-Case 'a reboot-requiring control is skipped without -AllowReboot' {
        Reset-Stub
        Set-Stub { function script:Get-AzLocalSecurityFeature { param($FeatureName, $Scope) script:Ok $false } }
        $outcome = Set-AzLocalSecurityBaseline -Scope Local -ControlId 'AZL-HVCI-001' -Confirm:$false
        Assert-Equal 'Skipped' $outcome.Outcome
        Assert-Match 'AllowReboot' $outcome.Message
        Assert-Equal 0 (Get-WriteCount)
    }

    Test-Case 'a reboot-requiring control proceeds with -AllowReboot' {
        Reset-Stub
        Set-Stub { function script:Get-AzLocalSecurityFeature { param($FeatureName, $Scope) script:Ok $false } }
        $outcome = Set-AzLocalSecurityBaseline -Scope Local -ControlId 'AZL-HVCI-001' -AllowReboot -Confirm:$false -WarningAction SilentlyContinue
        Assert-Equal 'Remediated' $outcome.Outcome
        Assert-Match 'reboot' $outcome.Message
        Assert-Equal 1 (Get-WriteCount 'Set-AzLocalSecurityFeature')
    }

    Test-Case 'a workload-pausing control is skipped without -AllowMaintenanceWindow' {
        Reset-Stub
        Set-Stub {
            function script:Get-AzLocalBitLockerVolume { param($VolumeType, $Scope)
                script:Ok @([pscustomobject]@{ MountPoint = 'C:\ClusterStorage\Volume1'; ProtectionStatus = 'Off' })
            }
        }
        $outcome = @(Set-AzLocalSecurityBaseline -Scope Local -ControlId 'AZL-BL-002' -Confirm:$false)
        Assert-Equal 'Skipped' $outcome[0].Outcome
        Assert-Match 'AllowMaintenanceWindow' $outcome[0].Message
        Assert-Equal 0 (Get-WriteCount)
    }

    Test-Case 'an Unknown control is never remediated' {
        Reset-Stub
        Set-Stub { function script:Get-AzLocalWdacMode { script:Fail 'not available' } }
        Set-AzLocalSecurityBaseline -Scope Local -ControlId 'AZL-WDAC-001' -Confirm:$false | Out-Null
        Assert-Equal 0 (Get-WriteCount)
    }

    Test-Case 'a control with no remediation reports NotSupported' {
        Reset-Stub
        Set-Stub { function script:Get-AzLocalSecureBootState { script:Ok $false } }
        $outcome = Set-AzLocalSecurityBaseline -Scope Local -ControlId 'AZL-HW-002' -Confirm:$false
        Assert-Equal 'NotSupported' $outcome.Outcome
    }

    Test-Case 'a failing write reports Failed with the underlying message' {
        Reset-Stub
        Set-Stub {
            function script:Get-AzLocalWdacMode { script:Ok 'Audit' }
            function script:Set-AzLocalWdacMode { param($Mode) [pscustomobject]@{ Ok = $false; Value = $null; Message = 'access denied' } }
        }
        $outcome = Set-AzLocalSecurityBaseline -Scope Local -ControlId 'AZL-WDAC-001' -Confirm:$false
        Assert-Equal 'Failed' $outcome.Outcome
        Assert-Equal 'access denied' $outcome.Message
    }

    Test-Case 'remediation can act on a supplied audit result set' {
        Reset-Stub
        Set-Stub { function script:Get-AzLocalWdacMode { script:Ok 'Audit' } }
        $audit = Test-AzLocalSecurityBaseline -Scope Local -ControlId 'AZL-WDAC-001'
        $outcome = $audit | Set-AzLocalSecurityBaseline -Scope Local -Confirm:$false
        Assert-Equal 'Remediated' $outcome.Outcome
    }

    Write-Host ''
    Write-Host 'Configuration handling' -ForegroundColor Cyan

    Test-Case 'a partial override merges over the default' {
        $path = Join-Path $temp 'partial.json'
        '{ "profile": "Contoso", "controls": { "AZL-PWD-001": { "parameters": { "minimumLength": 20 } } } }' |
            Set-Content -LiteralPath $path

        $config = & $module { param($p) Import-AzLocalBaselineConfig -Path $p } $path
        Assert-Equal 'Contoso' $config.profile
        Assert-Equal 20 $config.controls['AZL-PWD-001'].parameters.minimumLength
        Assert-True ($config.controls.ContainsKey('AZL-VBS-001')) 'untouched controls should survive the merge'
        Assert-True ($config.controls['AZL-WDAC-001'].parameters.desiredMode -eq 'Enforced') 'defaults should survive the merge'
    }

    Test-Case 'malformed JSON throws a clear error' {
        $path = Join-Path $temp 'broken.json'
        'this is not json {' | Set-Content -LiteralPath $path
        $threw = $false
        try { & $module { param($p) Import-AzLocalBaselineConfig -Path $p } $path }
        catch { $threw = $true; Assert-Match 'not valid JSON' $_.Exception.Message }
        Assert-True $threw 'expected a terminating error'
    }

    Test-Case 'a missing configuration file throws a clear error' {
        $threw = $false
        try { & $module { param($p) Import-AzLocalBaselineConfig -Path $p } (Join-Path $temp 'nope.json') }
        catch { $threw = $true; Assert-Match 'not found' $_.Exception.Message }
        Assert-True $threw 'expected a terminating error'
    }

    Write-Host ''
    Write-Host 'Reporting' -ForegroundColor Cyan

    Test-Case 'a report and its JSON sidecar are written' {
        Reset-Stub
        $path = Join-Path $temp 'report.html'
        Test-AzLocalSecurityBaseline -Scope Local | New-AzLocalSecurityReport -Path $path | Out-Null

        Assert-True (Test-Path $path) 'HTML missing'
        Assert-True (Test-Path ([System.IO.Path]::ChangeExtension($path, '.json'))) 'JSON sidecar missing'
        Assert-Match '<!doctype html>' (Get-Content $path -Raw)
    }

    Test-Case 'Unknown results are excluded from the compliance score' {
        Reset-Stub
        Set-Stub { function script:Get-AzLocalSecurityFeature { param($FeatureName, $Scope) script:Fail 'unavailable' } }
        $summary = Test-AzLocalSecurityBaseline -Scope Local |
            New-AzLocalSecurityReport -Path (Join-Path $temp 'unknown.html') -PassThru

        Assert-True ($summary.Unknown -gt 0) 'expected Unknown results'
        Assert-Equal ($summary.Compliant + $summary.NonCompliant + $summary.Unknown) $summary.Total
        Assert-Equal 100 $summary.ComplianceScore
    }

    Test-Case 'the score reflects findings' {
        Reset-Stub
        Set-Stub { function script:Get-AzLocalWdacMode { script:Ok 'Audit' } }
        $summary = Test-AzLocalSecurityBaseline -Scope Local |
            New-AzLocalSecurityReport -Path (Join-Path $temp 'score.html') -PassThru

        Assert-Equal 1 $summary.NonCompliant
        Assert-Equal 1 $summary.CriticalFindings
        Assert-True ($summary.ComplianceScore -lt 100) 'score should drop below 100'
    }

    Test-Case 'HTML in a value is escaped, not emitted as markup' {
        Reset-Stub
        Set-Stub {
            function script:Get-AzLocalSyslogForwarder { param($Scope)
                script:Ok ([pscustomobject]@{
                    ServerName = '<script>alert(1)</script>'; UseUDP = $false; NoEncryption = $false
                    SkipServerCertificateCheck = $false; SkipServerCNCheck = $false
                    ClientCertificateThumbprint = 'AABBCC'
                })
            }
        }
        $path = Join-Path $temp 'xss.html'
        Test-AzLocalSecurityBaseline -Scope Local -ControlId 'AZL-LOG-001' |
            New-AzLocalSecurityReport -Path $path | Out-Null

        $html = Get-Content $path -Raw
        Assert-True ($html -notmatch '<script>alert') 'raw script tag reached the report'
        Assert-Match '&lt;script&gt;' $html
    }

    Write-Host ''
    Write-Host 'State collection' -ForegroundColor Cyan

    Test-Case 'state collection reads without writing' {
        Reset-Stub
        $state = Get-AzLocalSecurityState -Scope Local
        Assert-Equal $true $state.Hardware.SecureBoot
        Assert-Equal $true $state.SecurityFeatures.VBS.Value
        Assert-Equal 0 (Get-WriteCount)
    }

    Test-Case 'state collection summarises keys without exposing them' {
        Reset-Stub
        $state = Get-AzLocalSecurityState -Scope Local
        Assert-Equal 1 $state.BitLocker.RecoveryKeySummary.KeyCount
        Assert-True (($state | ConvertTo-Json -Depth 8) -notmatch 'TOPSECRETKEYMATERIAL') 'key material leaked into state output'
    }
}
finally {
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ''
Write-Host "$script:Passed passed, $script:Failed failed." -ForegroundColor $(if ($script:Failed) { 'Red' } else { 'Green' })
Write-Host ''

exit $(if ($script:Failed) { 1 } else { 0 })
