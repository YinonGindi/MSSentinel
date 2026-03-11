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
- Permissions to create Logic Apps, Data Collection Endpoints/Rules, and assign Graph API roles

## Deployment

### 1. Create the custom Log Analytics table

Edit `createTable.ps1` with your tenant, subscription, resource group, and workspace names, then run it:

```powershell
.\createTable.ps1
```

This creates the `EPMElevationRequests_CL` table with all required columns.

### 2. Deploy the Data Collection Endpoint (DCE)

```bash
az deployment group create \
  --resource-group <RESOURCE_GROUP> \
  --template-file DCE_template.json \
  --parameters dataCollectionEndpointName=<DCE_NAME>
```

Note the **Logs Ingestion URL** from the deployment output.

### 3. Deploy the Data Collection Rule (DCR)

```bash
az deployment group create \
  --resource-group <RESOURCE_GROUP> \
  --template-file DCR_template.json \
  --parameters \
    dataCollectionRuleName=<DCR_NAME> \
    workspaceResourceId=<LOG_ANALYTICS_WORKSPACE_RESOURCE_ID> \
    endpointResourceId=<DCE_RESOURCE_ID_FROM_STEP_2>
```

Note the **DCR Immutable ID** from the deployment output.

### 4. Deploy the Logic App

```bash
az deployment group create \
  --resource-group <RESOURCE_GROUP> \
  --template-file azuredeploy.json \
  --parameters azuredeploy.parameters.json
```

Or with explicit parameters:

```bash
az deployment group create \
  --resource-group <RESOURCE_GROUP> \
  --template-file azuredeploy.json \
  --parameters \
    dceLogsIngestionUrl=<LOGS_INGESTION_URL_FROM_STEP_2> \
    dcrImmutableId=<DCR_IMMUTABLE_ID_FROM_STEP_3> \
    dcrStreamName=Custom-EPMElevationRequests
```

> The deployment outputs the Logic App's **Managed Identity Principal ID** — you'll need this in the next steps.

### 5. Grant Microsoft Graph permissions to the Managed Identity

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

### 6. Grant Monitoring Metrics Publisher role on the DCR

The Logic App's managed identity needs the **Monitoring Metrics Publisher** role on the Data Collection Rule to send data via the Logs Ingestion API.

```bash
az role assignment create \
  --assignee <PRINCIPAL_ID_FROM_DEPLOYMENT_OUTPUT> \
  --role "Monitoring Metrics Publisher" \
  --scope <DCR_RESOURCE_ID_FROM_STEP_3>
```

### 7. Verify

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
| `logicAppName` | string | `EPM-FetchElevationRequests` | Logic App resource name |
| `location` | string | Resource group location | Azure region |
| `recurrenceIntervalHours` | int | `24` | Run frequency in hours |
| `dceLogsIngestionUrl` | string | *(required)* | Logs Ingestion URL of the Data Collection Endpoint |
| `dcrImmutableId` | string | *(required)* | Immutable ID of the Data Collection Rule |
| `dcrStreamName` | string | `Custom-EPMElevationRequests` | Stream name declared in the DCR |

## License

MIT
