# Intune EPM Elevation Requests → Log Analytics

An Azure Logic App that fetches **Endpoint Privilege Management (EPM) elevation request** logs from the Microsoft Graph beta API and ingests them into a **Log Analytics** custom log table via the **Logs Ingestion API** (Data Collection Rule) for reporting, alerting, and Sentinel integration.

## Overview

| Component | Detail |
|---|---|
| **API** | `GET /beta/deviceManagement/elevationRequests` ([docs](https://learn.microsoft.com/en-us/graph/api/intune-epmgraphapiservice-privilegemanagementelevationrequest-list?view=graph-rest-beta)) |
| **Auth** | System-assigned Managed Identity (no secrets in the workflow) |
| **Pagination** | Automatic — follows `@odata.nextLink` until all pages are collected |
| **Sink** | Log Analytics custom table (`EPMElevationRequests_CL`) via DCR Logs Ingestion API |
| **Schedule** | Configurable recurrence (default: every 24 hours) |

## Repository files

| File | Description |
|---|---|
| `createTable.ps1` | PowerShell script to create (or migrate) the custom Log Analytics table |
| `DCR_template.json` | ARM template to deploy a Data Collection Rule (includes its own ingestion endpoint) |
| `azuredeploy.json` | ARM template to deploy the Logic App |
| `azuredeploy.parameters.json` | Example parameters file |

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
- **Azure PowerShell** (`Az` module) for running `createTable.ps1`
- Permissions to create Logic Apps, Data Collection Rules, and assign roles

## Deployment

### Step 1 — Create the custom table

```powershell
Connect-AzAccount
.\createTable.ps1 -WorkspaceResourceGroupName "<WORKSPACE_RG>" -WorkspaceName "<WORKSPACE_NAME>"
```

> If you already have a **classic** `EPMElevationRequests_CL` table, the script automatically migrates it to DCR-based.

### Step 2 — Deploy the Data Collection Rule (DCR)

The DCR uses `kind: "Direct"` so it provides its own Logs Ingestion endpoint — no separate Data Collection Endpoint (DCE) is needed.

```bash
az deployment group create \
  --resource-group <RESOURCE_GROUP> \
  --template-file DCR_template.json \
  --parameters \
    dcrName="EPMElevationRequests-dcr" \
    workspaceResourceId="/subscriptions/<SUB_ID>/resourceGroups/<WORKSPACE_RG>/providers/Microsoft.OperationalInsights/workspaces/<WORKSPACE_NAME>"
```

Note the **`logsIngestionEndpoint`** and **`dcrImmutableId`** from the outputs — you'll need them in Step 3.

### Step 3 — Deploy the Logic App

```bash
az deployment group create \
  --resource-group <RESOURCE_GROUP> \
  --template-file azuredeploy.json \
  --parameters \
    logsIngestionUrl="<LOGS_INGESTION_ENDPOINT_FROM_STEP_2>" \
    dcrImmutableId="<DCR_IMMUTABLE_ID_FROM_STEP_2>"
```

Note the **`managedIdentityPrincipalId`** from the outputs.

### Step 4 — Grant Monitoring Metrics Publisher role

The Logic App's managed identity needs **Monitoring Metrics Publisher** on the DCR to send data:

```bash
az role assignment create \
  --assignee "<MANAGED_IDENTITY_PRINCIPAL_ID>" \
  --role "Monitoring Metrics Publisher" \
  --scope "<DCR_RESOURCE_ID_FROM_STEP_2>"
```

### Step 5 — Grant Microsoft Graph permissions

The Logic App's managed identity needs `DeviceManagementConfiguration.Read.All` application permission on Microsoft Graph:

```powershell
# Install the module if needed
# Install-Module Microsoft.Graph -Scope CurrentUser

Connect-MgGraph -Scopes "AppRoleAssignment.ReadWrite.All"

$managedIdentityId = "<MANAGED_IDENTITY_PRINCIPAL_ID>"
$graphAppId        = "00000003-0000-0000-c000-000000000000"  # Microsoft Graph

$graphSP = Get-MgServicePrincipal -Filter "appId eq '$graphAppId'"
$appRole = $graphSP.AppRoles | Where-Object { $_.Value -eq "DeviceManagementConfiguration.Read.All" }

New-MgServicePrincipalAppRoleAssignment `
  -ServicePrincipalId $managedIdentityId `
  -PrincipalId $managedIdentityId `
  -ResourceId $graphSP.Id `
  -AppRoleId $appRole.Id
```

### Step 6 — Verify

1. Open the Logic App in the Azure portal
2. Click **Run Trigger** → **Recurrence** to manually trigger a run
3. Check the run history — expect `200 OK` from Graph and `204 No Content` from the DCE
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

### azuredeploy.json (Logic App)

| Parameter | Type | Default | Description |
|---|---|---|---|
| `logicAppName` | string | `EPM-FetchElevationRequests` | Logic App resource name |
| `location` | string | Resource group location | Azure region |
| `recurrenceIntervalHours` | int | `24` | Run frequency in hours |
| `logsIngestionUrl` | string | *(required)* | Logs Ingestion URL from the DCR |
| `dcrImmutableId` | string | *(required)* | Immutable ID of the DCR |
| `dcrStreamName` | string | `Custom-EPMElevationRequests` | DCR stream name |

### DCR_template.json

| Parameter | Type | Default | Description |
|---|---|---|---|
| `dcrName` | string | `EPMElevationRequests-dcr` | DCR resource name |
| `location` | string | Resource group location | Azure region |
| `workspaceResourceId` | string | *(required)* | Log Analytics workspace resource ID |

## License

MIT
