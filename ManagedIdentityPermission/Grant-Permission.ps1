function Get-AppIds ($AppName) {
    Get-MgServicePrincipal -Filter "displayName eq '$AppName'"
}

function Set-APIPermissions ($MSIName, $AppId, $PermissionName) {
    Write-Host "[+] Setting permission $PermissionName on $MSIName"
    $MSI = Get-AppIds -AppName $MSIName
    if ( $MSI.count -gt 1 )
    {
        Write-Host "[-] Found multiple principals with the same name." -ForegroundColor Red
        return 
    } elseif ( $MSI.count -eq 0 ) {
        Write-Host "[-] Principal not found." -ForegroundColor Red
        return 
    }
    Start-Sleep -Seconds 2 # Wait in case the MSI identity creation take some time
    $GraphServicePrincipal = Get-MgServicePrincipal -Filter "appId eq '$AppId'"
    $AppRole = $GraphServicePrincipal.AppRoles | Where-Object {$_.Value -eq $PermissionName -and $_.AllowedMemberTypes -contains "Application"}
    try
    {
        New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $MSI.Id -PrincipalId $MSI.Id -ResourceId $GraphServicePrincipal.Id -AppRoleId $AppRole.Id -ErrorAction Stop | Out-Null
    }
    catch
    {
        if ( $_.Exception.Message -eq "Permission being assigned already exists on the object" )
        {
            Write-Host "[-] $($_.Exception.Message)"
        } else {
            Write-Host "[-] $($_.Exception.Message)" -ForegroundColor Red
        }
        return
    }
    Write-Host "[+] Permission granted" -ForegroundColor Green
}



#MTP
Set-APIPermissions -MSIName "MI-Name" -AppId "8ee8fdad-f234-4243-8f3b-15c294843740" -PermissionName "Incident.Read.All"
Set-APIPermissions -MSIName "MI-Name" -AppId "8ee8fdad-f234-4243-8f3b-15c294843740" -PermissionName "AdvancedHunting.Read.All"
#MDE
Set-APIPermissions -MSIName "MI-Name" -AppId "fc780465-2017-40d4-a0c5-307022471b92" -PermissionName "AdvancedQuery.Read.All"
#Graph
Set-APIPermissions -MSIName "MI-Name" -AppId "00000003-0000-0000-c000-000000000000" -PermissionName "SecurityIncident.Read.All" 
