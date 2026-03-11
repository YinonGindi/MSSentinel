# Variables for Azure Subscription ID, Log Analytics Resource Group and Log Analytics Workspace name.
$TenantId = "[entra tenant id]"
$SubscriptionId = "[azure subscription id]"
$LogAnalyticsRG = "[sentinel law rg]"
$LogAnalyticsWorkspace = "[sentinel law name]"

# Connect to Azure
Connect-AzAccount -Tenant $TenantId
Set-AzContext -Subscription $SubscriptionId

# Create the custom table for EPM elevation requests
$tableParams = @'
{
   "properties": {
       "schema": {
              "name": "EPMElevationRequests_CL",
              "columns": [
                {
                    "name": "TimeGenerated",
                    "type": "datetime"
                },
                {
                    "name": "id",
                    "type": "string"
                },
                {
                    "name": "status",
                    "type": "string"
                },
                {
                    "name": "requestedByUserId",
                    "type": "string"
                },
                {
                    "name": "requestedByUserPrincipalName",
                    "type": "string"
                },
                {
                    "name": "requestedOnDeviceId",
                    "type": "string"
                },
                {
                    "name": "deviceName",
                    "type": "string"
                },
                {
                    "name": "requestCreatedDateTime",
                    "type": "datetime"
                },
                {
                    "name": "requestLastModifiedDateTime",
                    "type": "datetime"
                },
                {
                    "name": "requestJustification",
                    "type": "string"
                },
                {
                    "name": "requestExpiryDateTime",
                    "type": "datetime"
                },
                {
                    "name": "fileName",
                    "type": "string"
                },
                {
                    "name": "filePath",
                    "type": "string"
                },
                {
                    "name": "fileHash",
                    "type": "string"
                },
                {
                    "name": "fileDescription",
                    "type": "string"
                },
                {
                    "name": "publisherName",
                    "type": "string"
                },
                {
                    "name": "publisherCert",
                    "type": "string"
                },
                {
                    "name": "productName",
                    "type": "string"
                },
                {
                    "name": "productInternalName",
                    "type": "string"
                },
                {
                    "name": "productVersion",
                    "type": "string"
                },
                {
                    "name": "reviewCompletedByUserId",
                    "type": "string"
                },
                {
                    "name": "reviewCompletedByUserPrincipalName",
                    "type": "string"
                },
                {
                    "name": "reviewCompletedDateTime",
                    "type": "datetime"
                },
                {
                    "name": "reviewerJustification",
                    "type": "string"
                }
             ]
       }
   }
}
'@

Invoke-AzRestMethod -Path "/subscriptions/$SubscriptionID/resourcegroups/$LogAnalyticsRG/providers/microsoft.operationalinsights/workspaces/$LogAnalyticsWorkspace/tables/EPMElevationRequests_CL?api-version=2021-12-01-preview" -Method PUT -payload $tableParams
