# Intune EPM Elevation Requests → Log Analytics

An Azure Logic App that fetches **Endpoint Privilege Management (EPM) elevation request** logs from the Microsoft Graph beta API and ingests them into a **Log Analytics** custom log table for reporting, alerting, and Sentinel integration.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)]([[https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FYinonGindi%](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FYinonGindi%2FMSSentinel%2Frefs%2Fheads%2Fmain%2FConnectors%2FIntuneEPMElevationRequests%2Fazuredeploy.json)])

## Overview

| Component | Detail |
|---|---|
| **API** | `GET /beta/deviceManagement/elevationRequests` ([docs](https://learn.microsoft.com/en-us/graph/api/intune-epmgraphapiservice-privilegemanagementelevationrequest-list?view=graph-rest-beta)) |
| **Auth** | System-assigned Managed Identity (no secrets in the workflow) |
| **Pagination** | Automatic — follows `@odata.nextLink` until all pages are collected |
| **Sink** | Log Analytics custom log table (`EPMElevationRequests_CL`) |
| **Schedule** | Configurable recurrence (default: every 24 hours) |

## Data collected

Each record contains the following fields (flattened from the Graph response):

| Field | Description |
|---|---|
| `id` | Unique elevation request identifier |
| `status` | `pending`, `approved`, `denied`, `expired`, `revoked`, `completed` |
| `requestedByUserPrincipalName` | UPN of the end user who requested elevation |
| `requestedByUserId` | AAD object ID of the requesting user |
| `deviceName` | Device name where elevation was requested |
| `requestedOnDeviceId` | Intune device ID |
| `requestCreatedDateTime` | When the request was created (UTC) |
| `requestLastModifiedDateTime` | Last modification timestamp |
| `requestJustification` | Business justification provided by the user |
| `requestExpiryDateTime` | When the request expires |
| `fileName` | Executable file name |
| `filePath` | Full file path |
| `fileHash` | File hash |
| `fileDescription` | File description metadata |
| `publisherName` | Software publisher |
| `publisherCert` | Publisher certificate info |
| `productName` | Product name |
| `productInternalName` | Internal product name |
| `productVersion` | Product version |
| `reviewCompletedByUserPrincipalName` | UPN of the admin who reviewed the request |
| `reviewCompletedByUserId` | AAD object ID of the reviewer |
| `reviewCompletedDateTime` | When the review was completed |
| `reviewerJustification` | Justification provided by the reviewer |

## Prerequisites

- An Azure subscription
- An **Intune license** on the tenant (required for EPM Graph APIs)
- A **Log Analytics workspace**
- Permissions to create Logic Apps and assign Graph API roles

## Deployment

### 1. Deploy the ARM template

**Azure CLI:**

```bash
az deployment group create \
  --resource-group <RESOURCE_GROUP> \
  --template-file azuredeploy.json \
  --parameters azuredeploy.parameters.json
```

**PowerShell:**

```powershell
New-AzResourceGroupDeployment `
  -ResourceGroupName <RESOURCE_GROUP> `
  -TemplateFile azuredeploy.json `
  -TemplateParameterFile azuredeploy.parameters.json
```

> The deployment outputs the Logic App's **Managed Identity Principal ID** — you'll need this in the next step.

### 2. Grant Microsoft Graph permissions to the Managed Identity

The Logic App's managed identity needs the `DeviceManagementConfiguration.Read.All` application permission on Microsoft Graph.

```powershell
# Install the module if needed
# Install-Module Microsoft.Graph -Scope CurrentUser

Connect-MgGraph -Scopes "AppRoleAssignment.ReadWrite.All"

$managedIdentityId = "<PRINCIPAL_ID_FROM_DEPLOYMENT_OUTPUT>"
$graphAppId        = "00000003-0000-0000-c000-000000000000"  # Microsoft Graph

# Get the Graph service principal
$graphSP = Get-MgServicePrincipal -Filter "appId eq '$graphAppId'"

# Find the app role
$appRole = $graphSP.AppRoles | Where-Object { $_.Value -eq "DeviceManagementConfiguration.Read.All" }

# Assign the role
New-MgServicePrincipalAppRoleAssignment `
  -ServicePrincipalId $managedIdentityId `
  -PrincipalId $managedIdentityId `
  -ResourceId $graphSP.Id `
  -AppRoleId $appRole.Id
```

### 3. Authorize the Log Analytics API connection

After deployment, open the Azure Portal:

1. Navigate to **Resource Group** → **API Connections** → `azureloganalyticsdatacollector`
2. Click **Edit API connection**
3. Verify the Workspace ID and Key are correct, then click **Save**

### 4. Verify

1. Open the Logic App in the portal
2. Click **Run Trigger** → **Recurrence** to manually trigger a run
3. Check the run history to confirm a `200 OK` from Graph
4. Query Log Analytics:

```kql
EPMElevationRequests_CL
| sort by requestCreatedDateTime_t desc
| take 50
```

## KQL query examples

**Pending requests by user:**

```kql
EPMElevationRequests_CL
| where status_s == "pending"
| summarize Count = count() by requestedByUserPrincipalName_s
| sort by Count desc
```

**Denied requests with file details:**

```kql
EPMElevationRequests_CL
| where status_s == "denied"
| project requestCreatedDateTime_t, requestedByUserPrincipalName_s, deviceName_s,
          fileName_s, filePath_s, requestJustification_s, reviewerJustification_s
| sort by requestCreatedDateTime_t desc
```

**Elevation requests per day (trend):**

```kql
EPMElevationRequests_CL
| summarize Count = count() by bin(requestCreatedDateTime_t, 1d), status_s
| render timechart
```

## Parameters reference

| Parameter | Type | Default | Description |
|---|---|---|---|
| `logicAppName` | string | `EPM-FetchElevationRequests` | Logic App resource name |
| `location` | string | Resource group location | Azure region |
| `recurrenceIntervalHours` | int | `24` | Run frequency in hours |
| `logAnalyticsWorkspaceId` | string | *(required)* | Workspace ID |
| `logAnalyticsSharedKey` | securestring | *(required)* | Workspace shared key |
| `logAnalyticsLogType` | string | `EPMElevationRequests` | Custom log table name |

## License

MIT
