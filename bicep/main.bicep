/*
  Azure Local security baseline: the Azure-side half.

  The PowerShell module in this repository enforces and proves the baseline on
  the cluster itself. This deployment covers what the cluster cannot: continuous
  posture assessment, in-guest configuration auditing on the Arc-enabled nodes
  and workload VMs, and the Defender plan that provides behavioural threat
  detection rather than configuration checking.

  Together they produce the two artifacts an auditor asks for: the regulatory
  compliance report against the Microsoft Cloud Security Benchmark, and the
  drift and baseline state per node.

  Scope
    Subscription. Assignments made here are inherited by the resource group
    holding the Azure Local instance and by its Arc-enabled machines.

  Deploy
    az deployment sub create \
      --name azlocal-security-baseline \
      --location westeurope \
      --template-file main.bicep \
      --parameters @main.bicepparam
*/

targetScope = 'subscription'

@description('Azure region for the deployment metadata and for the policy assignment managed identities.')
param location string

@description('Short name identifying this Azure Local environment. Used in assignment names and display names.')
@minLength(2)
@maxLength(24)
param environmentName string

@description('Assign the Microsoft Cloud Security Benchmark initiative. This is what produces the regulatory compliance report in Defender for Cloud.')
param assignCloudSecurityBenchmark bool = true

@description('Assign the Azure compute security baseline audit for Windows machines, which covers the Arc-enabled Azure Local nodes and Windows workload VMs.')
param assignWindowsComputeBaseline bool = true

@description('Deploy the guest configuration prerequisites initiative. Azure Arc-enabled servers already carry the guest configuration agent inside the Connected Machine agent, so this is only needed when the subscription also holds Azure VMs that must be audited.')
param deployGuestConfigurationPrerequisites bool = false

@description('Enable the Microsoft Defender for Servers plan. Plan 2 adds file integrity monitoring and vulnerability assessment on top of Plan 1.')
param enableDefenderForServers bool = true

@allowed([
  'P1'
  'P2'
])
@description('Defender for Servers sub-plan.')
param defenderForServersPlan string = 'P2'

@description('Resource IDs to exclude from every assignment made here. Use sparingly and document each one: an exclusion is an unreviewed exception the next auditor will ask about.')
param exclusionScopes array = []

@description('Policy effect for the audit assignments. Keep this as AuditIfNotExists unless you have a specific reason to silence a control.')
@allowed([
  'AuditIfNotExists'
  'Disabled'
])
param auditEffect string = 'AuditIfNotExists'

// ---------------------------------------------------------------------------
// Built-in definition IDs
//
// Pinned by GUID rather than by name, because display names change between
// releases and a renamed definition would silently break the deployment.
// ---------------------------------------------------------------------------

var cloudSecurityBenchmarkInitiativeId = tenantResourceId(
  'Microsoft.Authorization/policySetDefinitions',
  '1f3afdf9-d0c9-4c3d-847f-89da613e70a8'
)

var windowsComputeBaselinePolicyId = tenantResourceId(
  'Microsoft.Authorization/policyDefinitions',
  '72650e9f-97bc-4b2a-ab5f-9781a9fcecbc'
)

var guestConfigurationPrerequisitesInitiativeId = tenantResourceId(
  'Microsoft.Authorization/policySetDefinitions',
  '12794019-7a00-42cf-95c2-882eed337cc8'
)

// Contributor. The guest configuration prerequisites initiative uses
// deployIfNotExists, so its managed identity needs rights to deploy the
// extension it is remediating.
var contributorRoleDefinitionId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  'b24988ac-6180-42a0-ab88-20f7382dd24c'
)

// Assignment names are capped at 24 characters by the platform.
var namePrefix = take(replace(toLower(environmentName), ' ', '-'), 12)

// ---------------------------------------------------------------------------
// Microsoft Cloud Security Benchmark
// ---------------------------------------------------------------------------

module cloudSecurityBenchmark 'modules/policyAssignment.bicep' = if (assignCloudSecurityBenchmark) {
  name: 'assign-mcsb-${namePrefix}'
  params: {
    assignmentName: take('${namePrefix}-mcsb', 24)
    displayName: 'Microsoft Cloud Security Benchmark (${environmentName})'
    assignmentDescription: 'Continuous posture assessment for the Azure Local environment ${environmentName}. This assignment is what produces the regulatory compliance report used as audit evidence.'
    policyDefinitionId: cloudSecurityBenchmarkInitiativeId
    location: location
    notScopes: exclusionScopes
    // The initiative is audit-only in its default configuration, so no managed
    // identity is required.
    assignIdentity: false
  }
}

// ---------------------------------------------------------------------------
// Azure compute security baseline for Windows machines
//
// Covers the Arc-enabled Azure Local nodes and any Windows workload VMs. This
// is the in-guest half of the picture: the PowerShell module proves the
// platform baseline, this proves the operating system baseline inside each
// machine.
// ---------------------------------------------------------------------------

module windowsComputeBaseline 'modules/policyAssignment.bicep' = if (assignWindowsComputeBaseline) {
  name: 'assign-winbaseline-${namePrefix}'
  params: {
    assignmentName: take('${namePrefix}-win-base', 24)
    displayName: 'Windows compute security baseline (${environmentName})'
    assignmentDescription: 'Audits Windows machines, including Arc-enabled Azure Local nodes, against the Azure compute security baseline.'
    policyDefinitionId: windowsComputeBaselinePolicyId
    location: location
    notScopes: exclusionScopes
    assignIdentity: false
    parameters: {
      effect: {
        value: auditEffect
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Guest configuration prerequisites
//
// Only needed for Azure VMs. Arc-enabled servers already have the guest
// configuration agent as part of the Connected Machine agent, so this defaults
// to off.
// ---------------------------------------------------------------------------

module guestConfigurationPrerequisites 'modules/policyAssignment.bicep' = if (deployGuestConfigurationPrerequisites) {
  name: 'assign-gcprereq-${namePrefix}'
  params: {
    assignmentName: take('${namePrefix}-gc-prereq', 24)
    displayName: 'Guest configuration prerequisites (${environmentName})'
    assignmentDescription: 'Deploys the guest configuration extension and system-assigned identity to Azure VMs so in-guest policies can evaluate them.'
    policyDefinitionId: guestConfigurationPrerequisitesInitiativeId
    location: location
    notScopes: exclusionScopes
    // deployIfNotExists needs an identity with rights to remediate.
    assignIdentity: true
  }
}

// The identity created by the assignment above needs Contributor to deploy the
// extension it remediates. Scoped to the subscription because that is the scope
// of the assignment.
resource guestConfigurationRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (deployGuestConfigurationPrerequisites) {
  name: guid(subscription().id, 'gc-prereq', environmentName)
  properties: {
    roleDefinitionId: contributorRoleDefinitionId
    principalId: deployGuestConfigurationPrerequisites ? guestConfigurationPrerequisites!.outputs.principalId : ''
    principalType: 'ServicePrincipal'
  }
}

// ---------------------------------------------------------------------------
// Microsoft Defender for Servers
//
// Configuration baselines catch what is misconfigured. This catches what is
// behaving badly: credential dumping, lateral movement, and an attacker using
// tooling that is already signed and allowed.
// ---------------------------------------------------------------------------

resource defenderForServers 'Microsoft.Security/pricings@2024-01-01' = if (enableDefenderForServers) {
  name: 'VirtualMachines'
  properties: {
    pricingTier: 'Standard'
    subPlan: defenderForServersPlan
  }
}

// ---------------------------------------------------------------------------
// Outputs
// ---------------------------------------------------------------------------

@description('Resource ID of the Microsoft Cloud Security Benchmark assignment, or an empty string when it was not assigned.')
output cloudSecurityBenchmarkAssignmentId string = assignCloudSecurityBenchmark ? cloudSecurityBenchmark!.outputs.assignmentId : ''

@description('Resource ID of the Windows compute security baseline assignment, or an empty string when it was not assigned.')
output windowsComputeBaselineAssignmentId string = assignWindowsComputeBaseline ? windowsComputeBaseline!.outputs.assignmentId : ''

@description('The Defender for Servers sub-plan that is now active, or "not enabled".')
output defenderForServersPlan string = enableDefenderForServers ? defenderForServersPlan : 'not enabled'
