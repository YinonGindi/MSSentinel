#Variable to Configure
$WorkspaceIDExisting="/subscriptions/<SUBID>/resourceGroups/<RG>/providers/Microsoft.OperationalInsights/workspaces/<SOURCE-LAW>"
$WorkspaceIDNew="/subscriptions/<SUBID>/resourceGroups/<RG>/providers/Microsoft.OperationalInsights/workspaces/<TARGET-LAW>"
$sourceTable="CustomLogs_CL"

#Get Token
$auth = Get-AzAccessToken

$AuthenticationHeader = @{ "Content-Type" = "application/json"; "Authorization" = "Bearer $(ConvertFrom-SecureString $auth.Token -AsPlainText)" }

$tableManagementAPIUrl = "https://management.azure.com$WorkspaceIDExisting/tables/$sourceTable`?api-version=2023-01-01-preview"
$response = Invoke-RestMethod -Uri $tableManagementAPIUrl -Method Get -Headers $AuthenticationHeader

$columns = $response.properties.schema.columns

$columnsToRemove = @("TenantId", "SourceSystem")
$updatedColumns = $columns | Where-Object { $columnsToRemove -notcontains $_.name }

$newTableUrl = "https://management.azure.com$WorkspaceIDNew/tables/$sourceTable`?api-version=2023-01-01-preview"

$body = (@{properties=@{schema=@{name=$sourceTable;columns=$updatedColumns};plan="Analytics";retentionInDays=90;totalRetentionInDays=90}} | ConvertTo-Json -Depth 6)

Invoke-RestMethod -Uri $newTableUrl -Method Put -Headers $AuthenticationHeader -Body $body -ContentType "application/json"
