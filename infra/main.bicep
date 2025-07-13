// Main infrastructure for GFaaS (Git Forensics as a Service)
// This creates Azure Function App and Static Web App for secret scanning

@minLength(1)
@maxLength(64)
@description('Name of the environment to deploy')
param environmentName string

@minLength(1)
@description('Primary location for all resources')
param location string

@description('Name of the resource group')
param resourceGroupName string = 'rg-${environmentName}'

@description('Optional GitHub token for private repositories')
@secure()
param githubToken string = ''

// Generate resource token for unique naming
var resourceToken = toLower(uniqueString(subscription().id, resourceGroup().id, environmentName))

// Resource naming convention: {prefix}-{resourceToken}
var prefix = 'gfaas'

// Create resource names
var logAnalyticsName = '${prefix}-logs-${resourceToken}'
var appInsightsName = '${prefix}-ai-${resourceToken}'
var keyVaultName = '${prefix}-kv-${resourceToken}'
var functionAppName = '${prefix}-func-${resourceToken}'
var staticWebAppName = '${prefix}-swa-${resourceToken}'
var storageAccountName = '${prefix}st${resourceToken}'
var managedIdentityName = '${prefix}-mi-${resourceToken}'

// Target scope
targetScope = 'resourceGroup'

// Create User-Assigned Managed Identity
resource managedIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: managedIdentityName
  location: location
  tags: {
    'azd-env-name': environmentName
  }
}

// Create Log Analytics Workspace
resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: logAnalyticsName
  location: location
  tags: {
    'azd-env-name': environmentName
  }
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 30
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
    }
  }
}

// Create Application Insights
resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: appInsightsName
  location: location
  kind: 'web'
  tags: {
    'azd-env-name': environmentName
  }
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: logAnalytics.id
    IngestionMode: 'LogAnalytics'
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
  }
}

// Create Key Vault for storing secrets
resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: keyVaultName
  location: location
  tags: {
    'azd-env-name': environmentName
  }
  properties: {
    sku: {
      family: 'A'
      name: 'standard'
    }
    tenantId: subscription().tenantId
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 7
    networkAcls: {
      defaultAction: 'Allow'
      bypass: 'AzureServices'
    }
  }
}

// Give the managed identity Key Vault Secrets User role
resource keyVaultSecretsUserRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, managedIdentity.id, 'Key Vault Secrets User')
  scope: keyVault
  properties: {
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      '4633458b-17de-408a-b874-0445c86b69e6'
    ) // Key Vault Secrets User
    principalId: managedIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// Store GitHub token in Key Vault if provided
resource githubTokenSecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = if (!empty(githubToken)) {
  parent: keyVault
  name: 'github-token'
  properties: {
    value: githubToken
  }
}

// Create Storage Account for Function App
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: storageAccountName
  location: location
  kind: 'StorageV2'
  sku: {
    name: 'Standard_LRS'
  }
  tags: {
    'azd-env-name': environmentName
  }
  properties: {
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false
    defaultToOAuthAuthentication: true
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    networkAcls: {
      defaultAction: 'Allow'
    }
  }
}

// Give the managed identity Storage Blob Data Owner role
resource storageRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storageAccount.id, managedIdentity.id, 'Storage Blob Data Owner')
  scope: storageAccount
  properties: {
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      'b7e6dc6d-f1e8-4753-8033-0f276bb0955b'
    ) // Storage Blob Data Owner
    principalId: managedIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// Give the managed identity Storage Blob Data Contributor role
resource storageBlobContributorRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storageAccount.id, managedIdentity.id, 'Storage Blob Data Contributor')
  scope: storageAccount
  properties: {
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      'ba92f5b4-2d11-453d-a403-e96b0029c9fe'
    ) // Storage Blob Data Contributor
    principalId: managedIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// Give the managed identity Storage Queue Data Contributor role
resource storageQueueContributorRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storageAccount.id, managedIdentity.id, 'Storage Queue Data Contributor')
  scope: storageAccount
  properties: {
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      '974c5e8b-45b9-4653-ba55-5f855dd0fb88'
    ) // Storage Queue Data Contributor
    principalId: managedIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// Give the managed identity Storage Table Data Contributor role
resource storageTableContributorRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storageAccount.id, managedIdentity.id, 'Storage Table Data Contributor')
  scope: storageAccount
  properties: {
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      '0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3'
    ) // Storage Table Data Contributor
    principalId: managedIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// Give the managed identity Storage File Data SMB Share Contributor role
resource storageFileContributorRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storageAccount.id, managedIdentity.id, 'Storage File Data SMB Share Contributor')
  scope: storageAccount
  properties: {
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      '0c867c2a-1d8c-454a-a3db-ab2ea1bdc8bb'
    ) // Storage File Data SMB Share Contributor
    principalId: managedIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// Give the managed identity Monitoring Metrics Publisher role
resource monitoringMetricsPublisherRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, managedIdentity.id, 'Monitoring Metrics Publisher')
  properties: {
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      '3913510d-42f4-4e42-8a64-420c390055eb'
    ) // Monitoring Metrics Publisher
    principalId: managedIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// Create Function App Service Plan (Consumption Plan)
resource functionAppServicePlan 'Microsoft.Web/serverfarms@2024-04-01' = {
  name: '${prefix}-plan-${resourceToken}'
  location: location
  tags: {
    'azd-env-name': environmentName
  }
  sku: {
    name: 'Y1'
    tier: 'Dynamic'
  }
  kind: 'functionapp'
  properties: {
    reserved: true // Linux
  }
}

// Create Function App
resource functionApp 'Microsoft.Web/sites@2024-04-01' = {
  name: functionAppName
  location: location
  kind: 'functionapp,linux'
  tags: {
    'azd-env-name': environmentName
    'azd-service-name': 'secretsniffer-api'
  }
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${managedIdentity.id}': {}
    }
  }
  dependsOn: [
    storageBlobContributorRole
    storageQueueContributorRole
    storageTableContributorRole
    storageFileContributorRole
  ]
  properties: {
    serverFarmId: functionAppServicePlan.id
    httpsOnly: true
    reserved: true
    clientAffinityEnabled: false
    publicNetworkAccess: 'Enabled'
    siteConfig: {
      linuxFxVersion: 'NODE|20'
      alwaysOn: false
      cors: {
        allowedOrigins: ['*']
        supportCredentials: false
      }
      appSettings: [
        {
          name: 'AzureWebJobsStorage'
          value: 'DefaultEndpointsProtocol=https;AccountName=${storageAccount.name};EndpointSuffix=${environment().suffixes.storage};AccountKey=${storageAccount.listKeys().keys[0].value}'
        }
        {
          name: 'FUNCTIONS_EXTENSION_VERSION'
          value: '~4'
        }
        {
          name: 'WEBSITE_NODE_DEFAULT_VERSION'
          value: '~20'
        }
        {
          name: 'FUNCTIONS_WORKER_RUNTIME'
          value: 'node'
        }
        {
          name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
          value: appInsights.properties.ConnectionString
        }
        {
          name: 'AzureWebJobsFeatureFlags'
          value: 'EnableWorkerIndexing'
        }
        {
          name: 'GITHUB_TOKEN'
          value: !empty(githubToken) ? '@Microsoft.KeyVault(VaultName=${keyVaultName};SecretName=github-token)' : ''
        }
        {
          name: 'KEY_VAULT_NAME'
          value: keyVaultName
        }
        {
          name: 'AZURE_CLIENT_ID'
          value: managedIdentity.properties.clientId
        }
      ]
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
      use32BitWorkerProcess: false
      healthCheckPath: '/api/health'
    }
  }
}

// Create diagnostic settings for Function App
resource functionAppDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'function-app-diagnostics'
  scope: functionApp
  properties: {
    workspaceId: logAnalytics.id
    logs: [
      {
        category: 'FunctionAppLogs'
        enabled: true
        retentionPolicy: {
          enabled: false
          days: 0
        }
      }
    ]
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
        retentionPolicy: {
          enabled: false
          days: 0
        }
      }
    ]
  }
}

// Create Static Web App
resource staticWebApp 'Microsoft.Web/staticSites@2024-04-01' = {
  name: staticWebAppName
  location: location
  tags: {
    'azd-env-name': environmentName
    'azd-service-name': 'secretsniffer-frontend'
  }
  sku: {
    name: 'Standard'
    tier: 'Standard'
  }
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${managedIdentity.id}': {}
    }
  }
  properties: {
    buildProperties: {
      skipGithubActionWorkflowGeneration: true
    }
    stagingEnvironmentPolicy: 'Enabled'
    allowConfigFileUpdates: true
    publicNetworkAccess: 'Enabled'
  }
}

// Configure Static Web App settings
resource staticWebAppSettings 'Microsoft.Web/staticSites/config@2024-04-01' = {
  parent: staticWebApp
  name: 'appsettings'
  properties: {
    VITE_API_URL: 'https://${functionApp.properties.defaultHostName}/api'
  }
}

// Outputs for other systems to use
output AZURE_LOCATION string = location
output AZURE_TENANT_ID string = subscription().tenantId
output AZURE_RESOURCE_GROUP string = resourceGroupName
output RESOURCE_GROUP_ID string = resourceGroup().id

output SERVICE_SECRETSNIFFER_FRONTEND_NAME string = staticWebApp.name
output SERVICE_SECRETSNIFFER_FRONTEND_RESOURCE_EXISTS bool = true
output SERVICE_SECRETSNIFFER_FRONTEND_URL string = 'https://${staticWebApp.properties.defaultHostname}'

output SERVICE_SECRETSNIFFER_API_NAME string = functionApp.name
output SERVICE_SECRETSNIFFER_API_RESOURCE_EXISTS bool = true
output SERVICE_SECRETSNIFFER_API_URL string = 'https://${functionApp.properties.defaultHostName}'

output AZURE_KEY_VAULT_NAME string = keyVault.name
output AZURE_KEY_VAULT_ENDPOINT string = keyVault.properties.vaultUri

output APPLICATIONINSIGHTS_CONNECTION_STRING string = appInsights.properties.ConnectionString
output AZURE_LOG_ANALYTICS_WORKSPACE_ID string = logAnalytics.properties.customerId

output AZURE_FUNCTION_APP_NAME string = functionApp.name
output AZURE_STATIC_WEB_APP_NAME string = staticWebApp.name
output AZURE_STORAGE_ACCOUNT_NAME string = storageAccount.name
output AZURE_MANAGED_IDENTITY_CLIENT_ID string = managedIdentity.properties.clientId
