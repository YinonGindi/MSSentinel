***

# Copy Log Analytics Custom Table Schema Between Workspaces

### PowerShell + ARM REST API (Preview 2023‑01‑01)

This guide explains how to **copy a custom Log Analytics table schema** (e.g., `CustomLogs_CL`) from one Log Analytics Workspace (LAW) to another using **PowerShell + the Log Analytics Tables Preview API**.

It is based on the official schema‑copy pattern provided in Microsoft’s internal auxiliary logs preview documentation.

***

## ✅ What This Script Does

*   Reads the schema of an existing **custom table** in a source LAW
*   Removes system‑reserved columns (`TenantId`, `SourceSystem`)
*   Recreates the same table in a target LAW
*   Supports `Analytics`, `Basic`, or `Auxiliary` table plans
*   Uses ARM REST API (required for preview table operations)

***

## ⚠️ Requirements

*   Azure RBAC: **Log Analytics Contributor** (or higher)

*   Must authenticate to the **correct tenant**

*   Must use **full ARM resource IDs** (not workspace GUIDs):
        /subscriptions/<SUBID>/resourceGroups/<RG>/providers/Microsoft.OperationalInsights/workspaces/<LAW>

*   Custom table names **must end with** `_CL`

***

## 🔧 Variables to Update

```powershell
$WorkspaceIDExisting = "/subscriptions/<SUBID>/resourceGroups/<RG>/providers/Microsoft.OperationalInsights/workspaces/<SOURCE-LAW>"
$WorkspaceIDNew      = "/subscriptions/<SUBID>/resourceGroups/<RG>/providers/Microsoft.OperationalInsights/workspaces/<TARGET-LAW>"

$sourceTable = "CustomLogs_CL"    # Must end with _CL
```

***

## 🔐 Authentication (ARM-scoped token)

```powershell
$auth = Get-AzAccessToken -ResourceUrl "https://management.azure.com/"
$AuthenticationHeader = @{
    "Authorization" = "Bearer $($auth.Token)"
    "Content-Type"  = "application/json"
}
```

***

## 📥 Step 1 — Read Schema From Source LAW

```powershell
$tableManagementAPIUrl = "https://management.azure.com$WorkspaceIDExisting/tables/$sourceTable?api-version=2023-01-01-preview"

$response = Invoke-RestMethod -Uri $tableManagementAPIUrl -Method GET -Headers $AuthenticationHeader

$columns = $response.properties.schema.columns
```

***

## 🧹 Step 2 — Remove Reserved Columns

```powershell
$columnsToRemove = @("TenantId", "SourceSystem")
$updatedColumns  = $columns | Where-Object { $columnsToRemove -notcontains $_.name }
```

***

## 🛠️ Step 3 — Build Request Body for New Table

```powershell
$bodyObject = @{
    properties = @{
        schema = @{
            name    = $newTable
            columns = $updatedColumns
        }
        plan = "Analytics"           # OR "Basic" / "Auxiliary"
        totalRetentionInDays = 90
        retentionInDays=90
    }
}

$body = $bodyObject | ConvertTo-Json -Depth 6
```

***

## 📤 Step 4 — Create New Table in Target LAW

```powershell
$newTableUrl = "https://management.azure.com$WorkspaceIDNew/tables/$newTable?api-version=2023-01-01-preview"

$result = Invoke-RestMethod -Uri $newTableUrl -Method PUT -Headers $AuthenticationHeader -Body $body
```

***

## 🔎 Validation

### List Tables

```powershell
$checkUrl = "https://management.azure.com$WorkspaceIDNew/tables?api-version=2023-01-01-preview"
Invoke-RestMethod -Uri $checkUrl -Method GET -Headers $AuthenticationHeader
```

### Inspect Created Table

```powershell
$schemaUrl = "https://management.azure.com$WorkspaceIDNew/tables/$newTable?api-version=2023-01-01-preview"
Invoke-RestMethod -Uri $schemaUrl -Method GET -Headers $AuthenticationHeader
```

***

## 🩹 Common Fixes

### ❌ InvalidAuthenticationToken

Likely causes:

*   Wrong tenant in Cloud Shell
    ```powershell
    Connect-AzAccount -Tenant <TENANT-ID>
    ```
*   Wrong token scope
    ```powershell
    Get-AzAccessToken -ResourceUrl "https://management.azure.com/"
    ```
*   Workspace ID missing `/subscriptions/...`

***
