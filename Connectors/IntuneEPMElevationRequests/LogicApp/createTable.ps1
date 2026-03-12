#Variables
$WorkspaceResourceGroupName=""
$WorkspaceName=""
$ErrorActionPreference = "Stop"
$SubscriptionId = (Get-AzContext).Subscription.Id
$TableName = "EPMElevationRequests_CL"
$ApiVersion = "2022-10-01"

$tablePath = "/subscriptions/$SubscriptionId/resourceGroups/$WorkspaceResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/tables/${TableName}?api-version=$ApiVersion"

# Check if table already exists
Write-Host "Checking for existing table '$TableName'..."
$existing = Invoke-AzRestMethod -Path $tablePath -Method GET

if ($existing.StatusCode -eq 200) {
    $tableObj = $existing.Content | ConvertFrom-Json
    if ($tableObj.properties.schema.tableSubType -eq "Classic") {
        Write-Host "Classic table found - migrating to DCR-based..."
        $migratePath = "/subscriptions/$SubscriptionId/resourceGroups/$WorkspaceResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/tables/${TableName}/migrate?api-version=2021-12-01-preview"
        $migrateResult = Invoke-AzRestMethod -Path $migratePath -Method POST
        if ($migrateResult.StatusCode -in 200, 202) {
            Write-Host "Migration initiated. Waiting 15 seconds..."
            Start-Sleep -Seconds 15
        } else {
            Write-Error "Migration failed. Status: $($migrateResult.StatusCode) Content: $($migrateResult.Content)"
            return
        }
    } else {
        Write-Host "Table already exists as DCR-based. Updating schema..."
    }
} else {
    Write-Host "Table does not exist. Creating new DCR-based table..."
}

$payload = @{
    properties = @{
        schema = @{
            name    = $TableName
            columns = @(
                @{ name = "TimeGenerated"; type = "datetime" }
                @{ name = "id"; type = "string" }
                @{ name = "status"; type = "string" }
                @{ name = "requestedByUserId"; type = "string" }
                @{ name = "requestedByUserPrincipalName"; type = "string" }
                @{ name = "requestedOnDeviceId"; type = "string" }
                @{ name = "deviceName"; type = "string" }
                @{ name = "requestCreatedDateTime"; type = "datetime" }
                @{ name = "requestLastModifiedDateTime"; type = "datetime" }
                @{ name = "requestJustification"; type = "string" }
                @{ name = "requestExpiryDateTime"; type = "datetime" }
                @{ name = "fileName"; type = "string" }
                @{ name = "filePath"; type = "string" }
                @{ name = "fileHash"; type = "string" }
                @{ name = "fileDescription"; type = "string" }
                @{ name = "publisherName"; type = "string" }
                @{ name = "publisherCert"; type = "string" }
                @{ name = "productName"; type = "string" }
                @{ name = "productInternalName"; type = "string" }
                @{ name = "productVersion"; type = "string" }
                @{ name = "reviewCompletedByUserId"; type = "string" }
                @{ name = "reviewCompletedByUserPrincipalName"; type = "string" }
                @{ name = "reviewCompletedDateTime"; type = "datetime" }
                @{ name = "reviewerJustification"; type = "string" }
            )
        }
        retentionInDays      = 30
        totalRetentionInDays = 30
    }
} | ConvertTo-Json -Depth 10

$result = Invoke-AzRestMethod -Path $tablePath -Method PUT -Payload $payload

if ($result.StatusCode -in 200, 202) {
    Write-Host "Table '$TableName' created/updated successfully." -ForegroundColor Green
} else {
    Write-Error "Failed to create table. Status: $($result.StatusCode) Content: $($result.Content)"
}

