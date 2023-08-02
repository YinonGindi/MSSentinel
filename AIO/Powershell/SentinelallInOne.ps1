param(
    [Parameter(Mandatory=$true)]$OrganizationName
)

#start stopwatch
$script:stopwatch =  [system.diagnostics.stopwatch]::StartNew()
#create log file location
$script:filep=$PSScriptRoot+'\'+((get-date).ToShortDateString()).Replace('/','')+'SentinelAIO.txt'

#Check if required files located
if(!(Test-Path "$PSScriptRoot\rgDelegatedResourceManagement.parameters.json")){
    Write-Output((GET-DATE -Format "dd/MM/yyy HH:mm")+" - [!] Missing rgDelegatedResourceManagement.parameters.json on $PSScriptRoot")| Tee-Object -FilePath $filep -Append
    break
}
if(!(Test-Path "$PSScriptRoot\rgDelegatedResourceManagement.json")){
    Write-Output((GET-DATE -Format "dd/MM/yyy HH:mm")+" - [!] Missing rgDelegatedResourceManagement.json on $PSScriptRoot")| Tee-Object -FilePath $filep -Append
    break
}
if(!(Test-Path "$PSScriptRoot\connectors.json")){
    Write-Output((GET-DATE -Format "dd/MM/yyy HH:mm")+" - [!] Missing connectors.json on $PSScriptRoot")| Tee-Object -FilePath $filep -Append
    break
}


function CheckModules($script:module) {
    $script:installedModule = Get-InstalledModule -Name $script:module -ErrorAction SilentlyContinue
    if ($null -eq $script:installedModule) {
        Write-Warning "The $script:module PowerShell module is not found"
        #check for Admin Privleges
        $script:currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())

        if (-not ($script:currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
            #Not an Admin, install to current user
            Write-Warning -Message "Can not install the $script:module module. You are not running as Administrator"
            Write-Warning -Message "Installing $script:module module to current user Scope"
            Install-Module -Name $script:module -Scope CurrentUser -Force
            Import-Module -Name $script:module -Force
        }
        else {
            #Admin, install to all users
            Write-Warning -Message "Installing the $script:module module to all users"
            Install-Module -Name $script:module -Force
            Import-Module -Name $script:module -Force
        }
    }
    #Install-Module will obtain the module from the gallery and install it on your local machine, making it available for use.
    #Import-Module will bring the module and its functions into your current powershell session, if the module is installed.  
}

CheckModules("Az.Resources")
CheckModules("Az.OperationalInsights")
CheckModules("Az.SecurityInsights")
CheckModules("Az.MonitoringSolutions")
CheckModules("Az.ManagementPartner")

$script:context = Get-AzContext 

Write-Host "`r`nIf not logged in to Azure already, you will now be asked to log in to your Azure environment. `nFor this script to work correctly, you need to provide credentials of a Global Admin or Security Admin for your organization. `nThis will allow the script to enable all required connectors.`r`n" -BackgroundColor Magenta
Read-Host -Prompt "[*] Press enter to continue or CTRL+C to quit the script" 


if(!$script:context){
    Connect-AzAccount
    $script:context = Get-AzContext
}
else{
    Write-Output((GET-DATE -Format "dd/MM/yyy HH:mm")+" - [$] Continuing as "+$script:context.Account+" with subscription id "+$script:context.Subscription.Id)| Tee-Object -FilePath $filep -Append
}

#select Subscription
$sublist=Get-AzSubscription
$count=1
if($sublist.Length -eq 1){
    $userselect=1
}
else{
    foreach($sub in $sublist){
        Write-Output((GET-DATE -Format "dd/MM/yyy HH:mm")+" - [$count] "+$sub.Name)
        $count++ 
    }
    $userselect=Read-Host "[*] Please select a subscription"
    #check for valid input
    while(1 -eq 1){
        if($sublist[$userselect-1] -eq $null){
            $userselect=Read-Host "[*] ERROR! Please enter a valid number"
        }
        else{
            break
        }
    }
}
Select-AzSubscription -SubscriptionId $sublist[$userselect-1].Id
$script:SubscriptionId=$script:sublist[$userselect-1].Id
$script:Workspace="LA-$OrganizationName-Sentinel"
$script:ConnectorsFile = "$PSScriptRoot\connectors.json"

#Create Resource Group
$script:RgExist=$true
$script:RG=Get-AzResourceGroup  -ErrorAction SilentlyContinue
while(1 -eq 1){
    Write-Output((GET-DATE -Format "dd/MM/yyy HH:mm")+" - [*] Select target resource group or create a new one")
    for($script:i=0;$script:i -lt $script:RG.ResourceGroupName.Length; $script:i++){
        Write-Output("     ["+($script:i+1)+"] "+$script:RG.ResourceGroupName[$script:i])
    }
    if("RG-$OrganizationName-Sentinel" -notin $script:RG.ResourceGroupName){
        $script:RgExist=$false
        Write-Output("     ["+($script:i+1)+"] Create new resource group named RG-$OrganizationName-Sentinel")
    }
    $script:uip=read-host "[*] Please choose resource group"
    if($script:uip -notin (1..($script:i+1))){
        Write-Output((GET-DATE -Format "dd/MM/yyy HH:mm")+" - [!] Error! Please try again and enter a valid number from the list")
    }
    else{
        if($script:uip -eq ($script:i+1) -and $script:RgExist){
            #select location for deployment
            $script:reglist=@("australiacentral","australiacentral2","australiaeast","australiasoutheast","brazilsouth","canadacentral","canadaeast","centralindia","centralus","eastasia","eastus","eastus2","francecentral"
            ,"francesouth","germanynorth","germanywestcentral","japaneast","japanwest","koreacentral","koreasouth","northcentralus","northeurope","norwayeast","norwaywest","southafricanorth","southafricawest","southcentralus","southeastasia","southindia","switzerlandnorth","switzerlandwest","uaecentral","uaenorth","uksouth","ukwest","westcentralus","westeurope","westindia","westus","westus2")
            $script:count=1
            write-output("")
            foreach($script:reg in $script:reglist){
                Write-Output((GET-DATE -Format "dd/MM/yyy HH:mm")+" - [$script:count] "+(Get-Culture).TextInfo.ToTitleCase($script:reg))
                $script:count++
            }
            write-output("")
            $script:userselect=Read-Host "[*] Please select a region"
            $script:Location=$script:reglist[$script:userselect-1]
            Write-Output((GET-DATE -Format "dd/MM/yyy HH:mm")+" - [$] Creating new resource group named: RG-$OrganizationName-Sentinel on $script:Location!")
            $script:ResourceGroup="RG-$OrganizationName-Sentinel"
            New-AzResourceGroup -Name $script:ResourceGroup -Location $script:Location | out-null
        }
        else{
            $script:Location=$script:RG.Location[$script:uip-1]
            $script:ResourceGroup=$script:RG.ResourceGroupName[$script:uip-1]
            Write-Output((GET-DATE -Format "dd/MM/yyy HH:mm")+" - [$] $script:ResourceGroup located on $script:Location is selected!") | Tee-Object -FilePath $filep -Append
        }
        break
    }
}

#Create Log Analytics workspace
try {

    $script:WorkspaceObject = Get-AzOperationalInsightsWorkspace -Name $script:Workspace -ResourceGroupName $script:ResourceGroup  -ErrorAction Stop
    $script:ExistingLocation = $script:WorkspaceObject.Location
    Write-Output((GET-DATE -Format "dd/MM/yyy HH:mm")+" - [$] Workspace named $script:Workspace in region $script:ExistingLocation already exists. Skipping...") | Tee-Object -FilePath $filep -Append

} catch {

    Write-Output((GET-DATE -Format "dd/MM/yyy HH:mm")+" - [*] Creating new workspace named $script:Workspace in region $script:Location...") | Tee-Object -FilePath $filep -Append
    # Create the new workspace for the given name, region, and resource group
    New-AzOperationalInsightsWorkspace -Location $script:Location -Name $script:Workspace -Sku pergb2018 -ResourceGroupName $script:ResourceGroup | out-null
    $script:WorkspaceObject = Get-AzOperationalInsightsWorkspace -Name $script:Workspace -ResourceGroupName $script:ResourceGroup  -ErrorAction Stop

}

$script:solutions = Get-AzOperationalInsightsIntelligencePack -resourcegroupname $script:ResourceGroup -WorkspaceName $script:Workspace -WarningAction:SilentlyContinue

if (($script:solutions | Where-Object Name -eq 'SecurityInsights').Enabled) {
    Write-Output((GET-DATE -Format "dd/MM/yyy HH:mm")+" - [!] Microsoft Sentinel is already installed on workspace $($script:Workspace)")| Tee-Object -FilePath $filep -Append
}
else {    
    New-AzMonitorLogAnalyticsSolution -Type SecurityInsights -ResourceGroupName $script:ResourceGroup -Location ($script:WorkspaceObject.Location) -WorkspaceResourceId $script:WorkspaceObject.ResourceId
}

$script:msTemplates = Get-AzSentinelAlertRuleTemplate -WorkspaceName $script:Workspace -ResourceGroupName $script:ResourceGroup | where Kind -EQ MicrosoftSecurityIncidentCreation

#Urls to be used for Sentinel API calls
$script:baseUri = "/subscriptions/${SubscriptionId}/resourceGroups/${ResourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${Workspace}"
$script:connectedDataConnectorsUri = "$script:baseUri/providers/Microsoft.SecurityInsights/dataConnectors/?api-version=2022-07-01-preview"

function Get-ConnectedDataconnectors{
    try {
            $script:allConnectedDataconnectors = (Invoke-AzRestMethod -Path $script:connectedDataConnectorsUri -Method GET).Content | ConvertFrom-Json			
        }
    catch {
        $script:errorReturn = $_
        Write-Error "Unable to invoke webrequest with error message: $script:errorReturn" -ErrorAction Stop
    }
    return $script:allConnectedDataconnectors
}

function checkDataConnector($script:dataConnector){
    $script:currentDataconnector = "" | Select-Object -Property guid,etag,isEnabled
    if ($script:allConnectedDataconnectors.value.Length -ne 0){
        foreach ($script:value in $script:allConnectedDataconnectors.value){			
            if ($script:value.kind -eq $script:dataConnector) {
                Write-Host "Successfully queried data connector $($script:value.kind) - already enabled"
                Write-Verbose $script:value
                
                $script:currentDataconnector.guid = $script:value.name
                $script:currentDataconnector.etag = $script:value.etag
                $script:currentDataconnector.isEnabled = $script:true
                break					
            }
        }
        if ($script:currentDataconnector.isEnabled -ne $script:true)
        {
            $script:currentDataconnector.guid = (New-Guid).Guid
            $script:currentDataconnector.etag = $null
            $script:currentDataconnector.isEnabled = $false
        }
    }
    else{        
        $script:currentDataconnector.guid = (New-Guid).Guid
        $script:currentDataconnector.etag = $null
        $script:currentDataconnector.isEnabled = $false
    }
    Write-Output($script:currentDataconnector)
    return $script:currentDataconnector
}

function BuildDataconnectorPayload($script:dataConnector, $script:guid, $script:etag, $script:isEnabled){    
    if ($script:dataConnector.kind -ne "AzureSecurityCenter")
    {
        $script:connectorProperties = $script:dataConnector.properties
        $script:connectorProperties | Add-Member -NotePropertyName tenantId -NotePropertyValue $script:context.Tenant.Id
    }
    else {
        $script:connectorProperties = $script:dataConnector.properties
        $script:connectorProperties | Add-Member -NotePropertyName subscriptionId -NotePropertyValue $script:SubscriptionId
    }	
    
    if ($script:isEnabled) {
		# Compose body for connector update scenario
		Write-Host "Updating data connector $($script:dataConnector.kind)"
		Write-Verbose "Name: $script:guid"
		Write-Verbose "Etag: $script:etag"
		
		$script:connectorBody = @{}

		$script:connectorBody | Add-Member -NotePropertyName kind -NotePropertyValue $script:dataConnector.kind -Force
		$script:connectorBody | Add-Member -NotePropertyName name -NotePropertyValue $script:guid -Force
		$script:connectorBody | Add-Member -NotePropertyName etag -NotePropertyValue $script:etag -Force
		$script:connectorBody | Add-Member -NotePropertyName properties -NotePropertyValue $script:connectorProperties
	}
	else {
		# Compose body for connector enable scenario
		Write-Host "$($script:dataConnector.kind) data connector is not enabled yet"
		Write-Host "Enabling data connector $($script:dataConnector.kind)"
        Write-Verbose "Name: $script:guid"
        
		$script:connectorBody = @{}

		$script:connectorBody | Add-Member -NotePropertyName kind -NotePropertyValue $script:dataConnector.kind -Force
		$script:connectorBody | Add-Member -NotePropertyName properties -NotePropertyValue $script:connectorProperties

	}
	return $script:connectorBody
}

function EnableOrUpdateDataconnector($script:baseUri, $script:guid, $script:connectorBody, $script:isEnabled){
    break 
    switch($script:guid){
        {$script:guid -eq $null -and $script:connector.kind -eq "AzureSecurityCenter"}{$script:guid="763f9fa1-c2d3-4fa2-93e9-bccd4899aa12"}
        {$script:guid -eq $null -and $script:connector.kind -eq"Office365"}{$script:guid="13143a7c-6e86-4c0b-9c4e-720ba910a82a"}
        {$script:guid -eq $null -and $script:connector.kind -eq"MicrosoftThreatProtection"}{$script:guid="MicrosoftThreatProtection"}
        {$script:guid -eq $null -and $script:connector.kind -eq"OfficeIrm"}{$script:guid="5e2b1b74-164f-455b-8157-15bfcb190226"}
        {$script:guid -eq $null -and $script:connector.kind -eq"AzureActiveDirectory"}{$script:guid="d331e394-0d6e-403d-a0b0-bcb257edbccc"}
    }
	$script:uri = "$script:baseUri/providers/Microsoft.SecurityInsights/dataConnectors/"+$script:guid+"?api-version=2022-07-01-preview"
	try {
		$script:result = Invoke-AzRestMethod -Path $script:uri -Method PUT -Payload ($script:connectorBody | ConvertTo-Json )
        Write-Output($script:result)
		if ($script:result.StatusCode -eq 200) {
			if ($script:isEnabled){
				Write-Host "Successfully updated data connector: $($script:connector.kind)" -ForegroundColor Green
			}
			else {
				Write-Host "Successfully enabled data connector: $($script:connector.kind)" -ForegroundColor Green
			}
		}
		else {
			Write-Error "Unable to enable data connector $($script:connector.kind) with error: $($script:result.Content)"
		}
		Write-Host ($script:body.Properties | Format-List | Format-Table | Out-String)
	}
	catch {
		$script:errorReturn = $_
		Write-Verbose $_
		Write-Error "Unable to invoke webrequest with error message: $script:errorReturn" -ErrorAction Stop
	}
}

function EnableMSAnalyticsRule($script:msProduct){
    Write-host("`r`n[!] Please enable the analytics rule for $script:msProduct! There is a bug on the module that need to be fixed")
    break
    try {
        foreach ($script:rule in $script:msTemplates){
            if ($script:rule.productFilter -eq $script:msProduct) {
                New-AzSentinelAlertRule -ResourceGroupName $script:ResourceGroup -WorkspaceName $script:Workspace -DisplayName $script:rule.displayName -MicrosoftSecurityIncidentCreation -Description $script:rule.description -ProductFilter $script:rule.productFilter  -AlertRuleTemplate $script:rule.Name
                Write-Host "Done!" -ForegroundColor Green
            }
        }
	}
	catch {
		$script:errorReturn = $_
		Write-verbose $_
		Write-Error "Unable to create analytics rule with error message: $script:errorReturn" -ErrorAction Stop
	}
}

#Getting all rules from file
$script:connectors = Get-Content -Raw -Path $script:ConnectorsFile | ConvertFrom-Json

#Getting all connected Data connectors
$script:allConnectedDataconnectors = Get-ConnectedDataconnectors

#add fusion rule
New-AzSentinelAlertRule -ResourceGroupName $script:ResourceGroup -WorkspaceName $script:Workspace -Kind 'Fusion' -AlertRuleTemplate "f71aba3d-28fb-450b-b192-4e76a83015c8" -ErrorAction SilentlyContinue

foreach ($script:connector in $script:connectors.connectors) {
    Write-Host "`r`nProcessing connector: " -NoNewline 
    Write-Host "$($script:connector.kind)" -ForegroundColor Blue

    #AzureActivityLog connector
     if ($script:connector.kind -eq "AzureActivityLog") {
        $script:SubNoHyphens = $script:SubscriptionId -replace '-',''
        $script:uri = "$script:baseUri/datasources/${$script:SubNoHyphens}?api-version=2020-08-01"
        $script:connectorBody = ""
        $script:activityEnabled = $false

        #Check if AzureActivityLog is already connected (there is no better way yet) [assuming there is only one AzureActivityLog from same subscription connected]
        try {
            # AzureActivityLog is already connected, compose body with existing etag for update
            $script:result = Invoke-AzRestMethod -Path $script:uri -Method GET
            if ($script:result.StatusCode -eq 200){
                Write-Host "Successfully queried data connector ${connector.kind} - already enabled"
                Write-Verbose $script:result
                Write-Host "Updating data connector $($script:connector.kind)"
                $script:activityEnabled = $script:true
            }
            elseif ($script:result.StatusCode -eq 405){
                Write-Host "$($script:connector.kind) method is not allowed"
            }
            else {
                Write-Host "$($script:connector.kind) data connector is not enabled yet"
                Write-Host "Enabling data connector $($script:connector.kind)"
                $script:activityEnabled = $false
            }
        }
        catch { 
            $script:errorReturn = $_
            Write-Error "Unable to invoke webrequest with error message: $script:errorReturn" -ErrorAction Stop
        }

        $script:connectorProperties = @{
            linkedResourceId = "/subscriptions/$script:SubscriptionId/providers/microsoft.insights/eventtypes/management"
        }        
        $script:connectorBody = @{}

        $script:connectorBody | Add-Member -NotePropertyName kind -NotePropertyValue $script:connector.kind -Force
        $script:connectorBody | Add-Member -NotePropertyName properties -NotePropertyValue $script:connectorProperties
        #Enable or Update AzureActivityLog Connector with http puth method
        try {
            $parameters=@{
                "logAnalytics"="/subscriptions/$script:SubscriptionId/resourcegroups/$script:ResourceGroup/providers/microsoft.operationalinsights/workspaces/$script:Workspace"
            }
            #$def = Get-AzPolicyDefinition -Id "/providers/Microsoft.Authorization/policyDefinitions/2465583e-4e78-4c15-b6be-a36cbc7c8b0f"
            #New-AzPolicyAssignment -Name "Configure Azure Activity logs to stream to Log Analytics" -Description "Deploys the diagnostic settings for Azure Activity to stream subscriptions audit logs to a Log Analytics workspace to monitor subscription-level events" -PolicyDefinition $def -Scope "/subscriptions/$script:SubscriptionId" -AssignIdentity -Location $Location -PolicyParameterObject $parameters
            Write-Host "Successfully enabled data connector: $($script:connector.kind)" -ForegroundColor Green 
            Write-Verbose ($script:body.Properties | Format-List | Format-Table | Out-String)
        }
        catch {
            $script:errorReturn = $_
            Write-host $_.Exception.Message
            Write-Host "Unable to enable data connector $($script:connector.kind) with error: $($script:result.Content)"
            Write-Error "Unable to invoke webrequest with error message: $script:errorReturn" -ErrorAction Stop
        }  
    }
    #MicrosoftDefenderforCloud connector
    elseif ($script:connector.kind -eq "AzureSecurityCenter") {  
        $script:dataConnectorBody = ""        
        #query for connected Data connectors
        $script:connectorProperties = checkDataConnector($script:connector.kind)
        $script:dataConnectorBody = BuildDataconnectorPayload $script:connector $script:connectorProperties.guid $script:connectorProperties.etag $script:connectorProperties.isEnabled
        EnableOrUpdateDataconnector $script:baseUri $script:connectorProperties.guid $script:dataConnectorBody $script:connectorProperties.isEnabled
        Write-Host "Adding Analytics Rule for data connector Microsoft Defender for Cloud..." -NoNewline
        EnableMSAnalyticsRule "Azure Security Center"
    }
    #Office365 connector
    elseif ($script:connector.kind -eq "Office365") {
        $script:dataConnectorBody = ""        
        #query for connected Data connectors
        $script:connectorProperties = checkDataConnector($script:connector.kind)
        $script:dataConnectorBody = BuildDataconnectorPayload $script:connector $script:connectorProperties.guid $script:connectorProperties.etag $script:connectorProperties.isEnabled
        EnableOrUpdateDataconnector $script:baseUri $script:connectorProperties.guid $script:dataConnectorBody $script:connectorProperties.isEnabled
    }
    #OfficeIRM connector
    elseif ($script:connector.kind -eq "OfficeIrm") {
        $script:dataConnectorBody = ""        
        #query for connected Data connectors
        $script:connectorProperties = checkDataConnector($script:connector.kind)
        $script:dataConnectorBody = BuildDataconnectorPayload $script:connector $script:connectorProperties.guid $script:connectorProperties.etag $script:connectorProperties.isEnabled
        EnableOrUpdateDataconnector $script:baseUri $script:connectorProperties.guid $script:dataConnectorBody $script:connectorProperties.isEnabled
        Write-Host "Adding Analytics Rule for data connector Microsoft 365 Insider Risk Management..." -NoNewline
        EnableMSAnalyticsRule "Microsoft 365 Insider Risk Management" 
    }
    #AzureAdvancedThreatProtection connector
    elseif ($script:connector.kind -eq "MicrosoftThreatProtection") {
        $script:dataConnectorBody = ""        
        #query for connected Data connectors
        $script:connectorProperties = checkDataConnector($script:connector.kind)
        $script:dataConnectorBody = BuildDataconnectorPayload $script:connector $script:connectorProperties.guid $script:connectorProperties.etag $script:connectorProperties.isEnabled
        EnableOrUpdateDataconnector $script:baseUri $script:connectorProperties.guid $script:dataConnectorBody $script:connectorProperties.isEnabled
        Write-Host "Adding Analytics Rule for data connector Azure Advanced Threat Protection..." -NoNewline
        EnableMSAnalyticsRule "Azure Advanced Threat Protection" 
    }
    ##Azure Active Directory Identity Protection connector
    elseif ($script:connector.kind -eq "AzureActiveDirectory") {
        $script:dataConnectorBody = ""        
        #query for connected Data connectors
        $script:connectorProperties = checkDataConnector($script:connector.kind)
        $script:dataConnectorBody = BuildDataconnectorPayload $script:connector $script:connectorProperties.guid $script:connectorProperties.etag $script:connectorProperties.isEnabled
        EnableOrUpdateDataconnector $script:baseUri $script:connectorProperties.guid $script:dataConnectorBody $script:connectorProperties.isEnabled
        Write-Host "Adding Analytics Rule for data connector Azure Active Directory Identity Protection..." -NoNewline
        EnableMSAnalyticsRule "Azure Active Directory Identity Protection" 
    }
}

#Create Lighthouse Delegation
(Get-Content "$PSScriptRoot\rgDelegatedResourceManagement.parameters.json").replace('<RGNAME>', $ResourceGroup) | Set-Content "$PSScriptRoot\rgDelegatedResourceManagement.parameters.json"
Register-AzResourceProvider -ProviderNamespace Microsoft.ManagedServices |Out-Null
New-AzManagementPartner -PartnerId 6144412
New-AzDeployment -Name "BDO_Managed_Sentinel" -Location $script:Location -TemplateFile "$PSScriptRoot\rgDelegatedResourceManagement.json" -TemplateParameterFile "$PSScriptRoot\rgDelegatedResourceManagement.parameters.json" -Verbose

#Create BDOCDCApp
try{
    $script:startDate = Get-Date
    $script:endDate = $script:startDate.AddYears(100)
    $script:NewSPN=New-AzADServicePrincipal -DisplayName BDOCDCApp -Role 'Log Analytics Reader' -Scope "/subscriptions/$script:SubscriptionId" -StartDate $script:startDate -EndDate $script:endDate
    New-AzRoleAssignment -ObjectId $script:NewSPN.Id -RoleDefinitionName 'Network Contributor' -Scope "/subscriptions/$script:SubscriptionId" |Out-Null
    $script:BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($script:NewSPN.Secret) 
    $script:UnsecureSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($script:BSTR)
    Write-Output("")| Tee-Object -FilePath $filep -Append
    Write-Output("----------------------------------------------------------------------")| Tee-Object -FilePath $filep -Append
    Write-Output((GET-DATE -Format "dd/MM/yyy HH:mm")+" - [$] TenantID: "+$script:context.Tenant.Id) | Tee-Object -FilePath $script:filep -Append
    Write-Output((GET-DATE -Format "dd/MM/yyy HH:mm")+" - [$] SubscriptionId: "+$script:SubscriptionId) | Tee-Object -FilePath $script:filep -Append
    Write-Output((GET-DATE -Format "dd/MM/yyy HH:mm")+" - [$] ApplicationID: "+$script:NewSPN.ApplicationId) | Tee-Object -FilePath $script:filep -Append
    Write-Output((GET-DATE -Format "dd/MM/yyy HH:mm")+" - [$] Secret ID: $script:UnsecureSecret") | Tee-Object -FilePath $script:filep -Append
    Write-Output((GET-DATE -Format "dd/MM/yyy HH:mm")+" - [*] Results is saved in: "+$filep)| Tee-Object -FilePath $filep -Append
    Write-Output((GET-DATE -Format "dd/MM/yyy HH:mm")+" - [*] Done in: "+$stopwatch.Elapsed.TotalSeconds.ToString()+" seconds!")| Tee-Object -FilePath $filep -Append
    Write-Output((GET-DATE -Format "dd/MM/yyy HH:mm")+" - [!] Please Delete the log file after sending to MDR! This contains sensitive information!")| Tee-Object -FilePath $filep -Append
    Disconnect-AzAccount |Out-Null
    Clear-AzContext |Out-Null
    read-host "Press Any key to continue..."
}
catch {
    $script:errorReturn = $_
    Write-host $_.Exception.Message
    Write-Error "[!] Error was raised: $script:errorReturn" -ErrorAction Stop
} 