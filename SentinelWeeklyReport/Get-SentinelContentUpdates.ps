param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$WorkspaceName
)


Connect-AzAccount -Identity -AccountId "caa2ee9f-e034-484f-a225-0b39638e5fc5" | out-null
# Construct the API URLs
$BaseUri = "https://management.azure.com"
$ResourcePath = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights"
$InstalledEndpoint = "contentPackages"
$AvailableEndpoint = "contentProductPackages"
$ApiVersionParam = "?api-version=2025-09-01"

$InstalledUri = "$BaseUri$ResourcePath/$InstalledEndpoint$ApiVersionParam"
$AvailableUri = "$BaseUri$ResourcePath/$AvailableEndpoint$ApiVersionParam"

function Get-ContentHubSolutions {
    param (
        [string]$Uri
    )

    try {
        $Response = Invoke-AzRestMethod -Method GET -Uri $Uri -ErrorAction Stop

        if ($Response.StatusCode -eq 200) {
            $Content = $Response.Content | ConvertFrom-Json
            return $Content.value
        }
        else {
            Write-Error "API call failed with status code: $($Response.StatusCode)"
            return $null
        }
    }
    catch {
        Write-Error "An error occurred: $($Error[0])"
        return $null
    }
}


function Export-ContentHubUpdatesToHtml {
    param (
        [Parameter(Mandatory = $true)]
        [Array]$UpdateData
    )
        
        try{
            if($UpdateData){
        $TableData = $UpdateData | ConvertTo-Html -Fragment -As Table
            }
        $FullHtml = @"
        <h2>Microsoft Sentinel Content Hub Updates Report</h2>
        <p>Total Solutions Requiring Updates: $($UpdateData.Count)</p>
        $TableData
"@
        Write-Output $FullHtml
    }
    catch {
        Write-Error "Failed to export HTML report: $($Error[0])"
    }
}

# Get both installed and available solutions
$InstalledSolutions = Get-ContentHubSolutions -Uri $InstalledUri
$AvailableSolutions = Get-ContentHubSolutions -Uri $AvailableUri
# Find solutions that need updates
$UpdateNeeded = foreach ($Installed in $InstalledSolutions) {
    $Available = $AvailableSolutions | Where-Object {
        $PSITEM.properties.displayName -eq $Installed.properties.displayName
    }

    if ($Available.properties.version -gt $Installed.properties.version) {
        [PSCustomObject]@{
            DisplayName = $Installed.properties.displayName
            CurrentVersion = $Installed.properties.version
            AvailableVersion = $Available.properties.version
        }
    }
}

if($UpdateNeeded){
    Export-ContentHubUpdatesToHtml -UpdateData $UpdateNeeded
}
else{
    Write-Output @"
    <h2>Microsoft Sentinel Content Hub Updates Report</h2>
        <p>Total Solutions Requiring Updates: 0</p>
"@
}
