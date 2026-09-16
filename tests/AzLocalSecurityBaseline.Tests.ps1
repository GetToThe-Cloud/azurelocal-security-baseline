#requires -Version 5.1
#requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
    Unit tests for AzLocalSecurityBaseline.

    Every test mocks the interop layer in Private/Interop.ps1, so the suite runs
    on any machine. Nothing here needs an Azure Local cluster, and nothing here
    touches the machine it runs on.
#>

BeforeAll {
    $script:ModulePath = Join-Path $PSScriptRoot '../src/AzLocalSecurityBaseline/AzLocalSecurityBaseline.psd1'
    Import-Module $script:ModulePath -Force

    # Probe result shapes, matching what Invoke-AzLocalProbe returns.
    function New-OkProbe {
        param($Value)
        [pscustomobject]@{ Ok = $true; Value = $Value; Reason = $null; Message = $null }
    }

    function New-FailedProbe {
        param([string] $Message = 'cmdlet not available', [string] $Reason = 'MissingCommand')
        [pscustomobject]@{ Ok = $false; Value = $null; Reason = $Reason; Message = $Message }
    }

    <#
        Puts the whole interop layer into a known-good state, so an individual
        test only has to override the one probe it cares about.
    #>
    function Set-HealthyCluster {
        InModuleScope AzLocalSecurityBaseline {
            Mock Get-AzLocalSecurityFeature { [pscustomobject]@{ Ok = $true; Value = $true; Message = $null } }
            Mock Get-AzLocalWdacMode { [pscustomobject]@{ Ok = $true; Value = 'Enforced'; Message = $null } }
            Mock Get-AzLocalWdacPolicyInventory {
                [pscustomobject]@{ Ok = $true; Message = $null; Value = @(
                    [pscustomobject]@{ PolicyName = 'AS_Base_Policy'; IsSystemPolicy = $true }
                ) }
            }
            Mock Get-AzLocalBitLockerVolume {
                [pscustomobject]@{ Ok = $true; Message = $null; Value = @(
                    [pscustomobject]@{ MountPoint = 'C:'; ProtectionStatus = 'On' }
                ) }
            }
            Mock Get-AzLocalBitLockerRecoveryKey {
                [pscustomobject]@{ Ok = $true; Message = $null; Value = @(
                    [pscustomobject]@{ ComputerName = 'NODE01'; PasswordID = 'x'; RecoveryKey = 'secret' }
                ) }
            }
            Mock Get-AzLocalSyslogForwarder {
                [pscustomobject]@{ Ok = $true; Message = $null; Value = [pscustomobject]@{
                    ServerName = 'siem.contoso.local'
                    UseUDP = $false
                    NoEncryption = $false
                    SkipServerCertificateCheck = $false
                    SkipServerCNCheck = $false
                    ClientCertificateThumbprint = 'AABBCC'
                } }
            }
            Mock Get-AzLocalDefenderStatus {
                [pscustomobject]@{ Ok = $true; Message = $null; Value = [pscustomobject]@{
                    RealTimeProtectionEnabled = $true
                    AMServiceEnabled = $true
                    AntivirusSignatureAge = 1
                } }
            }
            Mock Get-AzLocalDefenderPreference {
                [pscustomobject]@{ Ok = $true; Message = $null; Value = [pscustomobject]@{ PUAProtection = 1 } }
            }
            Mock Get-AzLocalTpm {
                [pscustomobject]@{ Ok = $true; Message = $null; Value = [pscustomobject]@{ TpmPresent = $true; TpmReady = $true } }
            }
            Mock Get-AzLocalSecureBootState { [pscustomobject]@{ Ok = $true; Value = $true; Message = $null } }
            Mock Get-AzLocalSolutionUpdateEnvironment {
                [pscustomobject]@{ Ok = $true; Message = $null; Value = [pscustomobject]@{
                    HealthState = 'Success'; CurrentVersion = '12.2608.1003.9'
                } }
            }
            Mock Get-AzLocalPasswordPolicy {
                [pscustomobject]@{ Ok = $true; Message = $null; Value = [pscustomobject]@{ MinimumPasswordLength = 14 } }
            }
            Mock Get-AzLocalLocalUser {
                [pscustomobject]@{ Ok = $true; Message = $null; Value = @(
                    [pscustomobject]@{ Name = 'ASBuiltInAdmin'; Enabled = $false; Rid = 500 }
                    [pscustomobject]@{ Name = 'ASBuiltInGuest'; Enabled = $false; Rid = 501 }
                ) }
            }
            Mock Get-AzLocalRegistryValue { [pscustomobject]@{ Ok = $true; Value = 'Authorised use only'; Message = $null } }

            # Write paths are mocked so a failing test can never change the host.
            Mock Set-AzLocalSecurityFeature { [pscustomobject]@{ Ok = $true; Value = $null; Message = $null } }
            Mock Set-AzLocalWdacMode { [pscustomobject]@{ Ok = $true; Value = $null; Message = $null } }
            Mock Enable-AzLocalBitLockerVolume { [pscustomobject]@{ Ok = $true; Value = $null; Message = $null } }
            Mock Set-AzLocalRegistryValue { [pscustomobject]@{ Ok = $true; Value = $null; Message = $null } }
            Mock Set-AzLocalPasswordPolicyLength { [pscustomobject]@{ Ok = $true; Value = $null; Message = $null } }
        }
    }
}

Describe 'Module surface' {
    It 'exports exactly the four supported functions' {
        $exported = (Get-Module AzLocalSecurityBaseline).ExportedFunctions.Keys | Sort-Object
        $exported | Should -Be @(
            'Get-AzLocalSecurityState'
            'New-AzLocalSecurityReport'
            'Set-AzLocalSecurityBaseline'
            'Test-AzLocalSecurityBaseline'
        )
    }

    It 'has a manifest whose FunctionsToExport matches the module' {
        $manifest = Import-PowerShellDataFile -Path $script:ModulePath
        $exported = (Get-Module AzLocalSecurityBaseline).ExportedFunctions.Keys | Sort-Object
        ($manifest.FunctionsToExport | Sort-Object) | Should -Be $exported
    }

    It 'only Set-AzLocalSecurityBaseline supports ShouldProcess' {
        (Get-Command Test-AzLocalSecurityBaseline).Parameters.Keys | Should -Not -Contain 'WhatIf'
        (Get-Command Set-AzLocalSecurityBaseline).Parameters.Keys | Should -Contain 'WhatIf'
    }
}

Describe 'Control registry' {
    It 'has unique control IDs' {
        InModuleScope AzLocalSecurityBaseline {
            $controls = Get-AzLocalControlRegistry
            $duplicates = $controls | Group-Object Id | Where-Object Count -gt 1
            $duplicates | Should -BeNullOrEmpty
        }
    }

    It 'gives every control a rationale and a reference' {
        InModuleScope AzLocalSecurityBaseline {
            foreach ($control in (Get-AzLocalControlRegistry)) {
                $control.Rationale | Should -Not -BeNullOrEmpty -Because "$($control.Id) needs a rationale"
                $control.Reference | Should -Match '^https://learn\.microsoft\.com/' -Because "$($control.Id) needs a Learn reference"
            }
        }
    }

    It 'has a default configuration entry for every control' {
        InModuleScope AzLocalSecurityBaseline {
            $config = Import-AzLocalBaselineConfig
            foreach ($control in (Get-AzLocalControlRegistry)) {
                $config.controls.ContainsKey($control.Id) | Should -BeTrue -Because "$($control.Id) is missing from baseline.default.json"
            }
        }
    }

    It 'has no configuration entry for a control that does not exist' {
        InModuleScope AzLocalSecurityBaseline {
            $config = Import-AzLocalBaselineConfig
            $ids = (Get-AzLocalControlRegistry).Id
            foreach ($key in $config.controls.Keys) {
                $ids | Should -Contain $key -Because "baseline.default.json references unknown control $key"
            }
        }
    }
}

Describe 'Test-AzLocalSecurityBaseline' {
    BeforeEach { Set-HealthyCluster }

    It 'reports every control compliant on a healthy system' {
        $results = Test-AzLocalSecurityBaseline -Scope Local
        $results | Should -Not -BeNullOrEmpty
        @($results | Where-Object Status -ne 'Compliant') | Should -BeNullOrEmpty
    }

    It 'never writes to the system during an audit' {
        Test-AzLocalSecurityBaseline -Scope Local | Out-Null
        InModuleScope AzLocalSecurityBaseline {
            Should -Invoke Set-AzLocalSecurityFeature -Times 0
            Should -Invoke Set-AzLocalWdacMode -Times 0
            Should -Invoke Enable-AzLocalBitLockerVolume -Times 0
            Should -Invoke Set-AzLocalPasswordPolicyLength -Times 0
            Should -Invoke Set-AzLocalRegistryValue -Times 0
        }
    }

    It 'flags Application Control left in audit mode' {
        InModuleScope AzLocalSecurityBaseline {
            Mock Get-AzLocalWdacMode { [pscustomobject]@{ Ok = $true; Value = 'Audit'; Message = $null } }
        }

        $result = Test-AzLocalSecurityBaseline -Scope Local -ControlId 'AZL-WDAC-001'
        $result.Status | Should -Be 'NonCompliant'
        $result.Severity | Should -Be 'Critical'
    }

    It 'flags an unencrypted cluster shared volume and names it' {
        InModuleScope AzLocalSecurityBaseline {
            Mock Get-AzLocalBitLockerVolume -ParameterFilter { $VolumeType -eq 'ClusterSharedVolume' } -MockWith {
                [pscustomobject]@{ Ok = $true; Message = $null; Value = @(
                    [pscustomobject]@{ MountPoint = 'C:\ClusterStorage\Volume1'; ProtectionStatus = 'On' }
                    [pscustomobject]@{ MountPoint = 'C:\ClusterStorage\Volume3'; ProtectionStatus = 'Off' }
                ) }
            }
        }

        $result = Test-AzLocalSecurityBaseline -Scope Local -ControlId 'AZL-BL-002'
        $result.Status | Should -Be 'NonCompliant'
        $result.Detail | Should -Match 'Volume3'
        $result.Actual | Should -Be '1/2 protected'
    }

    It 'flags unencrypted syslog transport' {
        InModuleScope AzLocalSecurityBaseline {
            Mock Get-AzLocalSyslogForwarder {
                [pscustomobject]@{ Ok = $true; Message = $null; Value = [pscustomobject]@{
                    ServerName = 'siem.contoso.local'
                    UseUDP = $true
                    NoEncryption = $true
                    SkipServerCertificateCheck = $false
                    SkipServerCNCheck = $false
                    ClientCertificateThumbprint = ''
                } }
            }
        }

        $result = Test-AzLocalSecurityBaseline -Scope Local -ControlId 'AZL-LOG-002'
        $result.Status | Should -Be 'NonCompliant'
        $result.Detail | Should -Match 'UDP transport'
        $result.Detail | Should -Match 'encryption disabled'
    }

    It 'reports Unknown, not Compliant, when a cmdlet is missing' {
        InModuleScope AzLocalSecurityBaseline {
            Mock Get-AzLocalSecurityFeature {
                [pscustomobject]@{ Ok = $false; Value = $null; Reason = 'MissingCommand'; Message = "The cmdlet 'Get-AzsSecurity' is not available." }
            }
        }

        $result = Test-AzLocalSecurityBaseline -Scope Local -ControlId 'AZL-VBS-001'
        $result.Status | Should -Be 'Unknown'
        $result.Detail | Should -Match 'not available'
    }

    It 'reports Unknown, not Compliant, when a control throws' {
        InModuleScope AzLocalSecurityBaseline {
            Mock Get-AzLocalTpm { throw 'catastrophic failure' }
        }

        $result = Test-AzLocalSecurityBaseline -Scope Local -ControlId 'AZL-HW-001' -WarningAction SilentlyContinue
        $result.Status | Should -Be 'Unknown'
    }

    It 'treats a mixed per-node feature result as non-compliant' {
        InModuleScope AzLocalSecurityBaseline {
            Mock Get-AzLocalSecurityFeature {
                [pscustomobject]@{ Ok = $true; Message = $null; Value = @(
                    [pscustomobject]@{ Value = $true }
                    [pscustomobject]@{ Value = $false }
                ) }
            }
        }

        $result = Test-AzLocalSecurityBaseline -Scope AllNodes -ControlId 'AZL-HVCI-001'
        $result.Status | Should -Be 'NonCompliant'
    }

    It 'flags an undocumented supplemental WDAC policy' {
        InModuleScope AzLocalSecurityBaseline {
            Mock Get-AzLocalWdacPolicyInventory {
                [pscustomobject]@{ Ok = $true; Message = $null; Value = @(
                    [pscustomobject]@{ PolicyName = 'AS_Base_Policy'; IsSystemPolicy = $true }
                    [pscustomobject]@{ PolicyName = 'MysteryAgent'; IsSystemPolicy = $false }
                ) }
            }
        }

        $result = Test-AzLocalSecurityBaseline -Scope Local -ControlId 'AZL-WDAC-002'
        $result.Status | Should -Be 'NonCompliant'
        $result.Detail | Should -Match 'MysteryAgent'
    }

    It 'honours an approved-policy allow list from configuration' {
        InModuleScope AzLocalSecurityBaseline {
            Mock Get-AzLocalWdacPolicyInventory {
                [pscustomobject]@{ Ok = $true; Message = $null; Value = @(
                    [pscustomobject]@{ PolicyName = 'AS_Base_Policy'; IsSystemPolicy = $true }
                    [pscustomobject]@{ PolicyName = 'VeeamAgent'; IsSystemPolicy = $false }
                ) }
            }
        }

        $configPath = Join-Path $TestDrive 'site.json'
        @{
            controls = @{
                'AZL-WDAC-002' = @{ parameters = @{ approvedPolicies = @('VeeamAgent') } }
            }
        } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $configPath

        $result = Test-AzLocalSecurityBaseline -Scope Local -ControlId 'AZL-WDAC-002' -ConfigPath $configPath
        $result.Status | Should -Be 'Compliant'
    }

    It 'skips controls disabled in configuration' {
        $configPath = Join-Path $TestDrive 'disabled.json'
        @{ controls = @{ 'AZL-SMB-002' = @{ enabled = $false } } } |
            ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $configPath

        $results = Test-AzLocalSecurityBaseline -Scope Local -ConfigPath $configPath
        @($results | Where-Object Id -eq 'AZL-SMB-002') | Should -BeNullOrEmpty

        $withSkipped = Test-AzLocalSecurityBaseline -Scope Local -ConfigPath $configPath -IncludeSkipped
        (@($withSkipped | Where-Object Id -eq 'AZL-SMB-002')[0]).Status | Should -Be 'Skipped'
    }

    It 'supports wildcard control filtering' {
        $results = Test-AzLocalSecurityBaseline -Scope Local -ControlId 'AZL-BL-*'
        @($results).Count | Should -Be 3
        @($results | Where-Object Category -ne 'Data at rest') | Should -BeNullOrEmpty
    }

    It 'never places recovery key material in a result' {
        $result = Test-AzLocalSecurityBaseline -Scope Local -ControlId 'AZL-BL-003'
        ($result | ConvertTo-Json -Depth 8) | Should -Not -Match 'secret'
    }
}

Describe 'Set-AzLocalSecurityBaseline' {
    BeforeEach { Set-HealthyCluster }

    It 'changes nothing when everything is compliant' {
        Set-AzLocalSecurityBaseline -Scope Local -Confirm:$false | Out-Null
        InModuleScope AzLocalSecurityBaseline {
            Should -Invoke Set-AzLocalWdacMode -Times 0
            Should -Invoke Set-AzLocalSecurityFeature -Times 0
        }
    }

    It 'changes nothing under -WhatIf and reports what it would do' {
        InModuleScope AzLocalSecurityBaseline {
            Mock Get-AzLocalWdacMode { [pscustomobject]@{ Ok = $true; Value = 'Audit'; Message = $null } }
        }

        $outcome = Set-AzLocalSecurityBaseline -Scope Local -ControlId 'AZL-WDAC-001' -WhatIf
        $outcome.Outcome | Should -Be 'WhatIf'

        InModuleScope AzLocalSecurityBaseline {
            Should -Invoke Set-AzLocalWdacMode -Times 0
        }
    }

    It 'remediates a non-compliant control when confirmed' {
        InModuleScope AzLocalSecurityBaseline {
            Mock Get-AzLocalWdacMode { [pscustomobject]@{ Ok = $true; Value = 'Audit'; Message = $null } }
        }

        $outcome = Set-AzLocalSecurityBaseline -Scope Local -ControlId 'AZL-WDAC-001' -Confirm:$false
        $outcome.Outcome | Should -Be 'Remediated'

        InModuleScope AzLocalSecurityBaseline {
            Should -Invoke Set-AzLocalWdacMode -Times 1 -ParameterFilter { $Mode -eq 'Enforced' }
        }
    }

    It 'refuses a reboot-requiring remediation without -AllowReboot' {
        InModuleScope AzLocalSecurityBaseline {
            Mock Get-AzLocalSecurityFeature { [pscustomobject]@{ Ok = $true; Value = $false; Message = $null } }
        }

        $outcome = Set-AzLocalSecurityBaseline -Scope Local -ControlId 'AZL-HVCI-001' -Confirm:$false
        $outcome.Outcome | Should -Be 'Skipped'
        $outcome.Message | Should -Match 'AllowReboot'

        InModuleScope AzLocalSecurityBaseline {
            Should -Invoke Set-AzLocalSecurityFeature -Times 0
        }
    }

    It 'performs a reboot-requiring remediation when -AllowReboot is supplied' {
        InModuleScope AzLocalSecurityBaseline {
            Mock Get-AzLocalSecurityFeature { [pscustomobject]@{ Ok = $true; Value = $false; Message = $null } }
        }

        $outcome = Set-AzLocalSecurityBaseline -Scope Local -ControlId 'AZL-HVCI-001' -AllowReboot -Confirm:$false -WarningAction SilentlyContinue
        $outcome.Outcome | Should -Be 'Remediated'
        $outcome.Message | Should -Match 'reboot'

        InModuleScope AzLocalSecurityBaseline {
            Should -Invoke Set-AzLocalSecurityFeature -Times 1 -ParameterFilter { $FeatureName -eq 'HVCI' -and $Enabled -eq $true }
        }
    }

    It 'refuses a workload-pausing remediation without -AllowMaintenanceWindow' {
        InModuleScope AzLocalSecurityBaseline {
            Mock Get-AzLocalBitLockerVolume {
                [pscustomobject]@{ Ok = $true; Message = $null; Value = @(
                    [pscustomobject]@{ MountPoint = 'C:\ClusterStorage\Volume1'; ProtectionStatus = 'Off' }
                ) }
            }
        }

        $outcome = Set-AzLocalSecurityBaseline -Scope Local -ControlId 'AZL-BL-002' -Confirm:$false
        $outcome.Outcome | Should -Be 'Skipped'
        $outcome.Message | Should -Match 'AllowMaintenanceWindow'

        InModuleScope AzLocalSecurityBaseline {
            Should -Invoke Enable-AzLocalBitLockerVolume -Times 0
        }
    }

    It 'never remediates a control whose state is Unknown' {
        InModuleScope AzLocalSecurityBaseline {
            Mock Get-AzLocalWdacMode { [pscustomobject]@{ Ok = $false; Value = $null; Message = 'not available' } }
        }

        Set-AzLocalSecurityBaseline -Scope Local -ControlId 'AZL-WDAC-001' -Confirm:$false | Out-Null

        InModuleScope AzLocalSecurityBaseline {
            Should -Invoke Set-AzLocalWdacMode -Times 0
        }
    }

    It 'reports NotSupported for a control with no remediation' {
        InModuleScope AzLocalSecurityBaseline {
            Mock Get-AzLocalSecureBootState { [pscustomobject]@{ Ok = $true; Value = $false; Message = $null } }
        }

        $outcome = Set-AzLocalSecurityBaseline -Scope Local -ControlId 'AZL-HW-002' -Confirm:$false
        $outcome.Outcome | Should -Be 'NotSupported'
    }

    It 'reports Failed when the underlying cmdlet fails' {
        InModuleScope AzLocalSecurityBaseline {
            Mock Get-AzLocalWdacMode { [pscustomobject]@{ Ok = $true; Value = 'Audit'; Message = $null } }
            Mock Set-AzLocalWdacMode { [pscustomobject]@{ Ok = $false; Value = $null; Message = 'access denied' } }
        }

        $outcome = Set-AzLocalSecurityBaseline -Scope Local -ControlId 'AZL-WDAC-001' -Confirm:$false
        $outcome.Outcome | Should -Be 'Failed'
        $outcome.Message | Should -Be 'access denied'
    }

    It 'acts on supplied audit results rather than re-reading state' {
        InModuleScope AzLocalSecurityBaseline {
            Mock Get-AzLocalWdacMode { [pscustomobject]@{ Ok = $true; Value = 'Audit'; Message = $null } }
        }

        $audit = Test-AzLocalSecurityBaseline -Scope Local -ControlId 'AZL-WDAC-001'
        $outcome = $audit | Set-AzLocalSecurityBaseline -Scope Local -Confirm:$false
        $outcome.Outcome | Should -Be 'Remediated'
    }
}

Describe 'Configuration handling' {
    It 'merges a partial override over the shipped default' {
        InModuleScope AzLocalSecurityBaseline {
            $path = Join-Path $TestDrive 'partial.json'
            @{ profile = 'Contoso'; controls = @{ 'AZL-PWD-001' = @{ parameters = @{ minimumLength = 20 } } } } |
                ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $path

            $config = Import-AzLocalBaselineConfig -Path $path
            $config.profile | Should -Be 'Contoso'
            $config.controls['AZL-PWD-001'].parameters.minimumLength | Should -Be 20
            # Untouched controls survive the merge.
            $config.controls.ContainsKey('AZL-VBS-001') | Should -BeTrue
        }
    }

    It 'throws a clear error on malformed JSON' {
        InModuleScope AzLocalSecurityBaseline {
            $path = Join-Path $TestDrive 'broken.json'
            'this is not json {' | Set-Content -LiteralPath $path
            { Import-AzLocalBaselineConfig -Path $path } | Should -Throw '*not valid JSON*'
        }
    }

    It 'throws when the configuration file does not exist' {
        InModuleScope AzLocalSecurityBaseline {
            { Import-AzLocalBaselineConfig -Path 'X:\nope.json' } | Should -Throw '*not found*'
        }
    }
}

Describe 'New-AzLocalSecurityReport' {
    BeforeEach { Set-HealthyCluster }

    It 'writes an HTML report and a JSON sidecar' {
        $results = Test-AzLocalSecurityBaseline -Scope Local
        $path = Join-Path $TestDrive 'report.html'

        $results | New-AzLocalSecurityReport -Path $path | Out-Null

        Test-Path $path | Should -BeTrue
        Test-Path ([System.IO.Path]::ChangeExtension($path, '.json')) | Should -BeTrue
        (Get-Content $path -Raw) | Should -Match '<!doctype html>'
    }

    It 'excludes Unknown results from the compliance score' {
        InModuleScope AzLocalSecurityBaseline {
            Mock Get-AzLocalSecurityFeature { [pscustomobject]@{ Ok = $false; Value = $null; Message = 'unavailable' } }
        }

        $results = Test-AzLocalSecurityBaseline -Scope Local
        $summary = $results | New-AzLocalSecurityReport -Path (Join-Path $TestDrive 'r2.html') -PassThru

        $summary.Unknown | Should -BeGreaterThan 0
        # 9 feature controls are Unknown; the rest are compliant, so the score is 100%
        # while the Unknown count carries the warning.
        $summary.ComplianceScore | Should -Be 100
        ($summary.Compliant + $summary.NonCompliant + $summary.Unknown) | Should -Be $summary.Total
    }

    It 'escapes HTML in values rather than emitting raw markup' {
        InModuleScope AzLocalSecurityBaseline {
            Mock Get-AzLocalSyslogForwarder {
                [pscustomobject]@{ Ok = $true; Message = $null; Value = [pscustomobject]@{
                    ServerName = '<script>alert(1)</script>'
                    UseUDP = $false; NoEncryption = $false
                    SkipServerCertificateCheck = $false; SkipServerCNCheck = $false
                    ClientCertificateThumbprint = 'AABBCC'
                } }
            }
        }

        $path = Join-Path $TestDrive 'xss.html'
        Test-AzLocalSecurityBaseline -Scope Local -ControlId 'AZL-LOG-001' |
            New-AzLocalSecurityReport -Path $path | Out-Null

        $html = Get-Content $path -Raw
        $html | Should -Not -Match '<script>alert'
        $html | Should -Match '&lt;script&gt;'
    }
}

Describe 'Get-AzLocalSecurityState' {
    BeforeEach { Set-HealthyCluster }

    It 'collects state without writing anything' {
        $state = Get-AzLocalSecurityState -Scope Local
        $state.Hardware.SecureBoot | Should -BeTrue
        $state.SecurityFeatures.VBS.Value | Should -BeTrue

        InModuleScope AzLocalSecurityBaseline {
            Should -Invoke Set-AzLocalSecurityFeature -Times 0
        }
    }

    It 'summarises recovery keys without exposing key material' {
        $state = Get-AzLocalSecurityState -Scope Local
        $state.BitLocker.RecoveryKeySummary.KeyCount | Should -Be 1
        ($state | ConvertTo-Json -Depth 8) | Should -Not -Match 'secret'
    }
}
