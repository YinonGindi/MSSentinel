# Intune EPM Elevation Requests → Log Analytics

An Azure Logic App that fetches **Endpoint Privilege Management (EPM) elevation request** logs from the Microsoft Graph beta API and ingests them into a **Log Analytics** custom log table via the **Logs Ingestion API** (Data Collection Endpoint / Data Collection Rule) for reporting, alerting, and Sentinel integration.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FYinonGindi%2FMSSentinel%2Frefs%2Fheads%2Fmain%2FConnectors%2FIntuneEPMElevationRequests%2Fazuredeploy.json)

## Overview

| Component | Detail |
|---|---|
| **API** | `GET /beta/deviceManagement/elevationRequests` ([docs](https://learn.microsoft.com/en-us/graph/api/intune-epmgraphapiservice-privilegemanagementelevationrequest-list?view=graph-rest-beta)) |
| **Auth** | System-assigned Managed Identity (no secrets in the workflow) |
| **Pagination** | Automatic — follows `@odata.nextLink` until all pages are collected |
| **Sink** | Log Analytics custom table (`EPMElevationRequests_CL`) via DCE/DCR Logs Ingestion API |
| **Schedule** | Configurable recurrence (default: every 24 hours) |

## What gets deployed

A single ARM template (`azuredeploy.json`) deploys all of the following:

| Resource | Type | Description |
|---|---|---|
| Custom table | `EPMElevationRequests_CL` | Log Analytics table with all EPM columns |
| Data Collection Endpoint | `<logicAppName>-dce` | Logs Ingestion API endpoint |
| Data Collection Rule | `<logicAppName>-dcr` | Routes data from the stream to the custom table |
| Logic App | `<logicAppName>` | Fetches EPM data from Graph and sends to DCE |
| Role assignment | Monitoring Metrics Publisher | Grants the Logic App permission to send data to the DCR |

## Data collected

Each record contains the following fields (flattened from the Graph response):

| Field | Type | Description |
|---|---|---|
| `TimeGenerated` | datetime | Maps to `requestCreatedDateTime` |
| `id` | string | Unique elevation request identifier |
| `status` | string | `pending`, `approved`, `denied`, `expired`, `revoked`, `completed` |
| `requestedByUserPrincipalName` | string | UPN of the end user who requested elevation |
| `requestedByUserId` | string | Entra object ID of the requesting user |
| `deviceName` | string | Device name where elevation was requested |
| `requestedOnDeviceId` | string | Intune device ID |
| `requestCreatedDateTime` | datetime | When the request was created (UTC) |
| `requestLastModifiedDateTime` | datetime | Last modification timestamp |
| `requestJustification` | string | Business justification provided by the user |
| `requestExpiryDateTime` | datetime | When the request expires |
| `fileName` | string | Executable file name |
| `filePath` | string | Full file path |
| `fileHash` | string | File hash |
| `fileDescription` | string | File description metadata |
| `publisherName` | string | Software publisher |
| `publisherCert` | string | Publisher certificate info |
| `productName` | string | Product name |
| `productInternalName` | string | Internal product name |
| `productVersion` | string | Product version |
| `reviewCompletedByUserPrincipalName` | string | UPN of the admin who reviewed the request |
| `reviewCompletedByUserId` | string | Entra object ID of the reviewer |
| `reviewCompletedDateTime` | datetime | When the review was completed |
| `reviewerJustification` | string | Justification provided by the reviewer |

## Prerequisites

- An Azure subscription
- An **Intune license** on the tenant (required for EPM Graph APIs)
- A **Log Analytics workspace**
- Permissions to create Logic Apps, Data Collection Endpoints/Rules, and assign roles

## Deployment

### 1. Deploy the ARM template

Click the **Deploy to Azure** button above, or use the CLI:

```bash
az deployment group create \
  --resource-group <RESOURCE_GROUP> \
  --template-file azuredeploy.json \
  --parameters \
    logAnalyticsWorkspaceName=<YOUR_WORKSPACE_NAME>
```

> The template creates everything automatically: custom table, DCE, DCR, Logic App, and the Monitoring Metrics Publisher role assignment. The deployment outputs the Logic App's **Managed Identity Principal ID** — you'll need this in the next step.

### 2. Grant Microsoft Graph permissions to the Managed Identity

The Logic App's managed identity needs the `DeviceManagementConfiguration.Read.All` application permission on Microsoft Graph. This is the only manual post-deployment step.

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

### 3. Verify

1. Open the Logic App in the portal
2. Click **Run Trigger** → **Recurrence** to manually trigger a run
3. Check the run history to confirm a `200 OK` from Graph and a `204 No Content` from the DCE
4. Query Log Analytics:

```kql
EPMElevationRequests_CL
| sort by requestCreatedDateTime desc
| take 50
```

## KQL query examples

**Pending requests by user:**

```kql
EPMElevationRequests_CL
| where status == "pending"
| summarize Count = count() by requestedByUserPrincipalName
| sort by Count desc
```

**Denied requests with file details:**

```kql
EPMElevationRequests_CL
| where status == "denied"
| project requestCreatedDateTime, requestedByUserPrincipalName, deviceName,
          fileName, filePath, requestJustification, reviewerJustification
| sort by requestCreatedDateTime desc
```

**Elevation requests per day (trend):**

```kql
EPMElevationRequests_CL
| summarize Count = count() by bin(requestCreatedDateTime, 1d), status
| render timechart
```

## Parameters reference

| Parameter | Type | Default | Description |
|---|---|---|---|
| `logicAppName` | string | `EPM-FetchElevationRequests` | Logic App resource name (also used to derive DCE/DCR names) |
| `location` | string | Resource group location | Azure region |
| `recurrenceIntervalHours` | int | `24` | Run frequency in hours |
| `logAnalyticsWorkspaceName` | string | *(required)* | Name of an existing Log Analytics workspace |
| `logAnalyticsWorkspaceRG` | string | Deployment resource group | Resource group of the workspace (if different) |

## License

MIT
