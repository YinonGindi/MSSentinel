param(
    [Parameter(Mandatory = $true)][string]$ResourceGroup,
    [Parameter(Mandatory = $true)][string]$Workspace,
    [Parameter(Mandatory = $true)][string]$Region,
    [Parameter(Mandatory = $false)][string[]]$SeveritiesToInclude = @("Informational", "Low", "Medium", "High")
)

$context = Get-AzContext


if (!$context) {
    Connect-AzAccount
    $context = Get-AzContext
}


Write-Host "Connected to Azure with subscription: " $context.Subscription
$context = Get-AzContext
$instanceProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
$profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($instanceProfile)
$token = $profileClient.AcquireAccessToken($context.Subscription.TenantId)
$authHeader = @{
    'Content-Type'  = 'application/json' 
    'Authorization' = 'Bearer ' + $token.AccessToken 
}
$SubscriptionId = $context.Subscription.Id


$baseUri = "https://management.azure.com/subscriptions/${SubscriptionId}/resourceGroups/${ResourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${Workspace}"
$alertUri = "$baseUri/providers/Microsoft.SecurityInsights/alertRules/"

#####
#create rules from any rule templates that came from solutions
#####

if (($SeveritiesToInclude -eq "None") -or ($null -eq $SeveritiesToInclude)) {
    Exit
}

#Give the system time to update all the needed databases before trying to install the rules.
Start-Sleep -Seconds 60

#URL to get all the needed Analytic Rule templates
$solutionURL = $baseUri + "/providers/Microsoft.SecurityInsights/contentTemplates?api-version=2023-05-01-preview"
#Add a filter only return analytic rule templates
$solutionURL += "&%24filter=(properties%2FcontentKind%20eq%20'AnalyticsRule')"

$results = (Invoke-RestMethod -Uri $solutionURL -Method Get -Headers $authHeader).value
  
$BaseAlertUri = $baseUri + "/providers/Microsoft.SecurityInsights/alertRules/"
$BaseMetaURI = $baseURI + "/providers/Microsoft.SecurityInsights/metadata/analyticsrule-"


Write-Host "Severities to include..." $SeveritiesToInclude
#Iterate through all the rule templates
foreach ($result in $results ) {
    #Make sure that the template's severity is one we want to include
    $severity = $result.properties.mainTemplate.resources.properties[0].severity
    Write-Host "Rule Template's severity is... " $severity 
    #Write-Host "condition is..." $SeveritiesToInclude.Contains($severity)   
    if ($SeveritiesToInclude.Contains($severity)) {
        Write-Host "Enabling alert rule template... " $result.properties.template.resources.properties.displayName

        $templateVersion = $result.properties.mainTemplate.resources.properties[1].version
        $template = $result.properties.mainTemplate.resources.properties[0]
        $kind = $result.properties.mainTemplate.resources.kind
        $displayName = $template.displayName
        $eventGroupingSettings = $template.eventGroupingSettings
        if ($null -eq $eventGroupingSettings) {
            $eventGroupingSettings = [ordered]@{aggregationKind = "SingleAlert" }
        }
        $body = ""
        $properties = $result.properties.mainTemplate.resources[0].properties
        $properties.enabled = $true
        #Add the field to link this rule with the rule template so that the rule template will show up as used
        #We had to use the "Add-Member" command since this field does not exist in the rule template that we are copying from.
        $properties | Add-Member -NotePropertyName "alertRuleTemplateName" -NotePropertyValue $result.properties.mainTemplate.resources[0].name
        $properties | Add-Member -NotePropertyName "templateVersion" -NotePropertyValue $result.properties.mainTemplate.resources[1].properties.version


        #Depending on the type of alert we are creating, the body has different parameters
        switch ($kind) {
            "MicrosoftSecurityIncidentCreation" {  
                $body = @{
                    "kind"       = "MicrosoftSecurityIncidentCreation"
                    "properties" = $properties
                }
            }
            "NRT" {
                $body = @{
                    "kind"       = "NRT"
                    "properties" = $properties
                }
            }
            "Scheduled" {
                $body = @{
                    "kind"       = "Scheduled"
                    "properties" = $properties
                }
                
            }
            Default { }
        }
        #If we have created the body...
        if ("" -ne $body) {
            #Create the GUId for the alert and create it.
            $guid = (New-Guid).Guid
            #Create the URI we need to create the alert.
            $alertUri = $BaseAlertUri + $guid + "?api-version=2022-12-01-preview"
            try {
                Write-Host "Attempting to create rule $($displayName)"
                $verdict = Invoke-RestMethod -Uri $alertUri -Method Put -Headers $authHeader -Body ($body | ConvertTo-Json -EnumsAsStrings -Depth 50)
                #Invoke-RestMethod -Uri $installURL -Method Put -Headers $authHeader -Body ($installBody | ConvertTo-Json -EnumsAsStrings -Depth 50)
                Write-Output "Succeeded"
                $solution = $allSolutions.properties | Where-Object -Property "contentId" -Contains $result.properties.packageId
                $metabody = @{
                    "apiVersion" = "2022-01-01-preview"
                    "name"       = "analyticsrule-" + $verdict.name
                    "type"       = "Microsoft.OperationalInsights/workspaces/providers/metadata"
                    "id"         = $null
                    "properties" = @{
                        "contentId" = $verdict.name
                        "parentId"  = $verdict.id
                        "kind"      = "AnalyticsRule"
                        "version"   = $templateVersion
                        "source"    = $solution.source
                        "author"    = $solution.author
                        "support"   = $solution.support
                    }
                }
                Write-Output "    Updating metadata...."
                $metaURI = $BaseMetaURI + $verdict.name + "?api-version=2022-01-01-preview"
                $metaVerdict = Invoke-RestMethod -Uri $metaURI -Method Put -Headers $authHeader -Body ($metabody | ConvertTo-Json -EnumsAsStrings -Depth 5)
                Write-Output "Succeeded"
            }
            catch {
                #The most likely error is that there is a missing dataset. There is a new
                #addition to the REST API to check for the existance of a dataset but
                #it only checks certain ones.  Hope to modify this to do the check
                #before trying to create the alert.
                $errorReturn = $_
                Write-Error $errorReturn
            }
            #This pauses for 5 second so that we don't overload the workspace.
            Start-Sleep -Seconds 1
        }
    }
}

return $return
