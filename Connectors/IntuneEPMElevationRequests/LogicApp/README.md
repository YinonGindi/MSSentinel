# Intune EPM Elevation Requests → Log Analytics

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FYinonGindi%2FMSSentinel%2Fmain%2FConnectors%2FIntuneEPMElevationRequests%2FLogicApp%2Fazuredeploy.json)

An Azure Logic App that fetches **Endpoint Privilege Management (EPM) elevation request** logs from the Microsoft Graph beta API and ingests them into a **Log Analytics** custom log table via the **Logs Ingestion API** (Data Collection Rule) for reporting, alerting, and Sentinel integration.

## Overview

| Component | Detail |
|---|---|
| **API** | `GET /beta/deviceManagement/elevationRequests` ([docs](https://learn.microsoft.com/en-us/graph/api/intune-epmgraphapiservice-privilegemanagementelevationrequest-list?view=graph-rest-beta)) |
| **Auth** | System-assigned Managed Identity (no secrets in the workflow) |
| **Filtering** | Only fetches records modified in the last 5 minutes (`$filter` on `requestLastModifiedDateTime`) |
| **Pagination** | Automatic — follows `@odata.nextLink` using `union()` until all pages are collected |
| **Sink** | Log Analytics custom table (`EPMElevationRequests_CL`) via DCR Logs Ingestion API |
| **Schedule** | Configurable recurrence (default: every 24 hours) |

## What the template deploys

A single ARM template (`azuredeploy.json`) creates all required resources:

| Resource | Purpose |
|---|---|
| **Custom Log Analytics table** | `EPMElevationRequests_CL` — created via nested cross-RG deployment in the workspace's resource group |
| **Data Collection Rule** | `kind: "Direct"` — provides its own Logs Ingestion endpoint (no separate DCE needed) |
| **Logic App** | Fetches EPM data from Graph API and sends it to Log Analytics |
| **Role assignment** | Grants the Logic App's managed identity **Monitoring Metrics Publisher** on the DCR |

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
- A **Log Analytics workspace** (can be in a different resource group)
- Permissions to create Logic Apps, Data Collection Rules, tables in Log Analytics, and assign roles

## Deployment

### Step 1 — Deploy

Click the **Deploy to Azure** button above, or run:

```bash
az deployment group create \
  --resource-group <RESOURCE_GROUP> \
  --template-file azuredeploy.json \
  --parameters \
    workspaceResourceGroup="<WORKSPACE_RG>" \
    workspace="<WORKSPACE_NAME>"
```

The template automatically creates the custom table, DCR, Logic App, and role assignment.

Note the **`managedIdentityPrincipalId`** from the outputs — you'll need it in Step 2.

> **Note:** If you have an existing **classic** `EPMElevationRequests_CL` table, you must migrate it first by running `createTable.ps1` before deploying.

### Step 2 — Verify Monitoring Metrics Publisher role

The template automatically assigns the **Monitoring Metrics Publisher** role to the Logic App's managed identity on the DCR. If the assignment failed (e.g. insufficient RBAC permissions during deployment), assign it manually:

```bash
az role assignment create \
  --assignee "<MANAGED_IDENTITY_PRINCIPAL_ID>" \
  --role "Monitoring Metrics Publisher" \
  --scope "/subscriptions/<SUB_ID>/resourceGroups/<RESOURCE_GROUP>/providers/Microsoft.Insights/dataCollectionRules/<DCR_NAME>"
```

Or via the Azure portal: **DCR → Access control (IAM) → Add role assignment → Monitoring Metrics Publisher → assign to the Logic App's managed identity**.

### Step 3 — Grant Microsoft Graph permissions

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

### Step 4 — Verify

1. Open the Logic App in the Azure portal
2. Click **Run Trigger** → **Recurrence** to manually trigger a run
3. Check the run history — expect `200 OK` from Graph and `204 No Content` from the ingestion endpoint
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
| `dcrName` | string | `DCR-EPMElevationRequests` | DCR resource name |
| `location` | string | Resource group location | Azure region |
| `workspace` | string | *(required)* | Workspace name for Log Analytics where Microsoft Sentinel is setup |
| `workspaceResourceGroup` | string | *(required)* | Resource Group for Log Analytics where Microsoft Sentinel is setup |
| `recurrenceIntervalHours` | int | `24` | Run frequency in hours |

## License

MIT
