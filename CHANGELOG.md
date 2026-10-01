# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-10-01

### Added

- `New-AzLocalSecurityRemoteTarget` for WinRM/PSSession and Azure Arc Run Command.
- Remote execution for audit, state collection and guarded remediation.
- Remote target, transport, execution id and evaluation status in results/reports.
- Arc Run Command support for node-local scope with structured output blobs.

### Changed

- A run containing only `Unknown` results is reported as incomplete rather than compliant.
- Documentation and examples now start from a management computer.

## [1.0.0] - 2026-09-15

### Added

- `Test-AzLocalSecurityBaseline`, read-only audit across 26 controls.
- `Set-AzLocalSecurityBaseline`, opt-in remediation with `-WhatIf`, gated
  behind `-AllowReboot` and `-AllowMaintenanceWindow`.
- `Get-AzLocalSecurityState`, raw state collection for evidence and
  troubleshooting.
- `New-AzLocalSecurityReport`, self-contained HTML report with a JSON sidecar.
- JSON desired-state configuration, merged over a shipped default profile.
- Bicep for the Microsoft Cloud Security Benchmark initiative, the Azure
  compute security baseline audit, guest configuration prerequisites and the
  Defender for Servers plan.
- Dependency-free smoke tests and a Pester 5 suite, both of which stub every
  call into Azure Local so they run anywhere.
