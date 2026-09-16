/*
  A single subscription-scope policy assignment.

  Wrapped in a module so that main.bicep reads as a list of decisions rather
  than a wall of repeated resource blocks, and so the identity and role plumbing
  lives in one place.
*/

targetScope = 'subscription'

@description('Assignment name. Maximum 24 characters, enforced by the platform.')
@maxLength(24)
param assignmentName string

@description('Display name shown in the Azure portal.')
param displayName string

@description('Why this assignment exists. Worth writing properly: this is what the next person reads before deciding whether to remove it.')
param assignmentDescription string

@description('Resource ID of the policy definition or policy set definition to assign.')
param policyDefinitionId string

@description('Region for the managed identity, when one is created.')
param location string

@description('Scopes excluded from the assignment.')
param notScopes array = []

@description('Parameters passed to the policy or initiative.')
param parameters object = {}

@description('Create a system-assigned managed identity. Required for deployIfNotExists and modify effects, unnecessary for audit-only assignments.')
param assignIdentity bool = false

@description('Enforcement mode. DoNotEnforce evaluates and reports without applying any effect, which is the way to trial an assignment.')
@allowed([
  'Default'
  'DoNotEnforce'
])
param enforcementMode string = 'Default'

resource assignment 'Microsoft.Authorization/policyAssignments@2024-04-01' = {
  name: assignmentName
  location: assignIdentity ? location : null
  identity: assignIdentity ? { type: 'SystemAssigned' } : { type: 'None' }
  properties: {
    displayName: displayName
    description: assignmentDescription
    policyDefinitionId: policyDefinitionId
    notScopes: notScopes
    parameters: parameters
    enforcementMode: enforcementMode
  }
}

@description('Resource ID of the assignment.')
output assignmentId string = assignment.id

@description('Principal ID of the assignment identity, or an empty string when no identity was created.')
output principalId string = assignIdentity ? assignment.identity.principalId! : ''

@description('The assignment name, echoed for convenience when scripting remediation tasks.')
output assignmentName string = assignment.name
