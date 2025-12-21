Copy Log Analytics Custom Table Schema Between Workspaces
PowerShell + ARM REST API (2023‑01‑01‑preview)
This guide explains how to copy the schema of a custom Log Analytics table (tables ending with _CL) from one Log Analytics Workspace (LAW) to another using PowerShell and the Log Analytics Tables Preview API.
This approach:

Reads the existing table schema from the source LAW
Removes reserved system columns
Recreates the table in the target LAW
Works fully via ARM REST (required for preview APIs)
Supports custom tables only


🔧 Requirements

Azure RBAC: Log Analytics Contributor (minimum)
You must log in to the same tenant where the LAW exists:
PowerShellConnect-AzAccount -Tenant "<TENANT-ID>"Show more lines

Full Workspace Resource IDs, not workspace GUIDs
Format:
/subscriptions/<SUBID>/resourceGroups/<RG>/providers/Microsoft.OperationalInsights/workspaces/<LAW>




🔁 Variables to Update
PowerShell$WorkspaceIDExisting = "/subscriptions/<SUBID>/resourceGroups/<RG>/providers/Microsoft.OperationalInsights/workspaces/<SOURCE-LAW>"$WorkspaceIDNew      = "/subscriptions/<SUBID>/resourceGroups/<RG>/providers/Microsoft.OperationalInsights/workspaces/<TARGET-LAW>"$sourceTable = "CustomLogs_CL"   # table to copy (must end with _CL)$newTable    = $sourceTable       # or set a new name ending in _CLShow more lines

🔐 Authentication
Request an ARM-scoped access token (critical!):
PowerShell$auth = Get-AzAccessToken -ResourceUrl "https://management.azure.com/"$AuthenticationHeader = @{    "Authorization" = "Bearer $($auth.Token)"    "Content-Type"  = "application/json"}Show more lines

📥 Step 1 — Read schema from source LAW
PowerShell$tableManagementAPIUrl = "https://management.azure.com$WorkspaceIDExisting/tables/$sourceTable?api-version=2023-01-01-preview"$response = Invoke-RestMethod -Method GET -Uri $tableManagementAPIUrl -Headers $AuthenticationHeader$columns  = $response.properties.schema.columnsShow more lines

🧹 Step 2 — Remove reserved columns
PowerShell$columnsToRemove = @("TenantId","SourceSystem")$updatedColumns  = $columns | Where-Object { $columnsToRemove -notcontains $_.name }Show more lines

🏗️ Step 3 — Build body for new table

Use totalRetentionInDays — NOT retentionInDays
Set plan to: Analytics, Basic, or Auxiliary

PowerShell$bodyObject = @{    properties = @{        schema = @{            name    = $newTable            columns = $updatedColumns        }        plan                = "Analytics"        totalRetentionInDays = 90    }}$body = $bodyObject | ConvertTo-Json -Depth 6Show more lines

📤 Step 4 — Create new table in target LAW
PowerShell$newTableUrl = "https://management.azure.com$WorkspaceIDNew/tables/$newTable?api-version=2023-01-01-preview"$result = Invoke-RestMethod -Method PUT -Uri $newTableUrl -Headers $AuthenticationHeader -Body $body -ContentType "application/json"Show more lines

✅ Validation
List tables:
PowerShellInvoke-RestMethod -Method GET `  -Uri "https://management.azure.com$WorkspaceIDNew/tables?api-version=2023-01-01-preview" `  -Headers $AuthenticationHeaderShow more lines
Get the created table schema:
PowerShellInvoke-RestMethod -Method GET `  -Uri "https://management.azure.com$WorkspaceIDNew/tables/$newTable?api-version=2023-01-01-preview" `  -Headers $AuthenticationHeaderShow more lines

❗ Common Fixes
InvalidAuthenticationToken

Wrong tenant
→ Connect-AzAccount -Tenant <TENANT-ID>
Wrong token scope
→ must use:
Get-AzAccessToken -ResourceUrl "https://management.azure.com/"
WorkspaceID missing /subscriptions/... prefix

400 BadRequest

Table name missing _CL
Using retentionInDays instead of totalRetentionInDays
$newTable undefined
$updatedColumns empty
