#Variable to Configure
$WorkspaceIDExisting="/subscriptions/00000000-0000-0000-0000-00000000000/resourceGroups/oiautorest6685/providers/Microsoft.OperationalInsights/workspaces/oiautorest6685"
$WorkspaceIDNew="/subscriptions/00000000-0000-0000-0000-00000000000/resourceGroups/oiautorest6685/providers/Microsoft.OperationalInsights/workspaces/oiautorest6685123123"
$sourceTable="CustomLogs_CL"

#Get Token
$auth = Get-AzAccessToken

$AuthenticationHeader = @{ "Content-Type" = "application/json"; "Authorization" = "Bearer $($auth.Token)" }

$tableManagementAPIUrl = "https://management.azure.com$WorkspaceIDExisting/tables/$sourceTable`?api-version=2023-01-01-preview"
$response = Invoke-RestMethod -Uri $tableManagementAPIUrl -Method Get -Headers $AuthenticationHeader

$columns = $response.properties.schema.columns

$columnsToRemove = @("TenantId", "SourceSystem")
$updatedColumns = $columns | Where-Object { $columnsToRemove -notcontains $_.name }

$newTableUrl = "https://management.azure.com$WorkspaceIDNew/tables/$sourceTable`?api-version=2023-01-01-preview"

$body = (@{properties=@{schema=@{name=$sourceTable;columns=$updatedColumns};plan="Analytics";retentionInDays=90}} | ConvertTo-Json -Depth 6)

Invoke-RestMethod -Uri $newTableUrl -Method Put -Headers $AuthenticationHeader -Body $body -ContentType "application/json"
