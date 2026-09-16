/*
  Example parameters. Copy this file per environment rather than editing it in
  place, so the committed example stays a working reference.
*/

using './main.bicep'

param location = 'westeurope'
param environmentName = 'sittard'

// Posture assessment and the regulatory compliance report. Leave both on.
param assignCloudSecurityBenchmark = true
param assignWindowsComputeBaseline = true

// Arc-enabled servers already carry the guest configuration agent. Turn this on
// only if the subscription also holds Azure VMs that need auditing.
param deployGuestConfigurationPrerequisites = false

// Behavioural threat detection on the nodes and the Arc VMs.
param enableDefenderForServers = true
param defenderForServersPlan = 'P2'

param auditEffect = 'AuditIfNotExists'

// Every entry here is an exception somebody will have to justify. Keep it empty
// if you can, and put the reason in the commit message if you cannot.
param exclusionScopes = []
