# Intune EPM Elevation Requests for Microsoft Sentinel

Deploy the **Intune EPM Elevation Requests** CCF connector for **Microsoft Sentinel** directly from this repository.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FYinonGindi%2FMSSentinel%2Fmain%2FConnectors%2FIntuneEPMElevationRequests%2FCCF%2Fintuneepmelevationrequests.json)

## ARM template

- **Template file:** [`intuneepmelevationrequests.json`](https://github.com/YinonGindi/MSSentinel/blob/main/Connectors/IntuneEPMElevationRequests/CCF/intuneepmelevationrequests.json)
- **Raw template URL:** `https://raw.githubusercontent.com/YinonGindi/MSSentinel/main/Connectors/IntuneEPMElevationRequests/CCF/intuneepmelevationrequests.json`

## What this deploys

This template deploys the **Intune EPM Elevation Requests** solution and supporting resources for Microsoft Sentinel, including the custom table, DCE, DCR, connector definition, and connector content template.

## Required parameters

During deployment, Azure will prompt for:

- `workspace` - The Log Analytics workspace name where Microsoft Sentinel is enabled
- `workspace-location` - The Azure region of that workspace

## After deployment

After the template deployment completes:

1. Open **Microsoft Sentinel** in the target workspace.
2. Go to **Data connectors**.
3. Open **Intune EPM Elevation Requests**.
4. Provide the **Client ID** and **Client Secret** for your Microsoft Entra application when prompted.

## Required Microsoft Graph permission

The application used for the connector should have:

- `DeviceManagementConfiguration.Read.All` (Application permission)

## Manual deployment link

If the button above doesn't work, use this direct deployment URL:

```text
https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FYinonGindi%2FMSSentinel%2Fmain%2FConnectors%2FIntuneEPMElevationRequests%2FCCF%2Fintuneepmelevationrequests.json
