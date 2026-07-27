# Microsoft 365 Admin Audit for Microsoft Sentinel

Deploy the **Microsoft 365 Admin Audit** CCF connector for **Microsoft Sentinel** directly from this repository.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FYinonGindi%2FMicrosoft_Sentinel%2Fmain%2FConnectors%2FM365AdminAudit%2FAdminAudit.json)

## ARM template

- **Template file:** [`AdminAudit.json`](https://github.com/YinonGindi/Microsoft_Sentinel/blob/main/Connectors/M365AdminAudit/AdminAudit.json)
- **Raw template URL:** `https://raw.githubusercontent.com/YinonGindi/Microsoft_Sentinel/main/Connectors/M365AdminAudit/AdminAudit.json`

## What this deploys

This template deploys the **Microsoft 365 Admin Audit** solution (version 3.0.0) and supporting resources for Microsoft Sentinel, including the connector definition, the custom **`M365AdminAudit_CL`** table (321 columns supporting all Office 365 record types and workloads), the Data Collection Endpoint (DCE), the Data Collection Rule (`M365AuditGeneralDCR`), and the connector content template.

Data is ingested from the **Office 365 Management Activity API** (`Audit.General` content type).

## Required parameters

During deployment, Azure will prompt for:

- `workspace` - The Log Analytics workspace name where Microsoft Sentinel is enabled
- `workspace-location` - The Azure region of that workspace

The `resourceGroupName` and `subscription` parameters default to the deployment resource group and subscription.

## Required permissions

The Entra ID application used for the connector must have:

- **Office 365 Management APIs - `ActivityFeed.Read`** (Application permission), with admin consent granted
- An active subscription to the **`Audit.General`** content type (started via the Office 365 Management Activity API)

Deployment also requires **read and write** permissions on the target Log Analytics workspace.

## After deployment

After the template deployment completes:

1. Register an Entra ID application (e.g. `Sentinel-M365Audit`) and create a **client secret**. Note the **Application (client) ID** and the secret **Value**.
2. Under the app's **API permissions**, add **Office 365 Management APIs** > **Application permissions** > **`ActivityFeed.Read`**, then **Grant admin consent**.
3. Subscribe to the **`Audit.General`** content type using the Office 365 Management Activity API (PowerShell script is provided in the connector instructions).
4. Open **Microsoft Sentinel** in the target workspace, go to **Data connectors**, open **Microsoft 365 Admin Audit**, and provide the **Client ID** and **Client Secret** when prompted.

## Manual deployment link

If the button above doesn't work, use this direct deployment URL:

```text
https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FYinonGindi%2FMicrosoft_Sentinel%2Fmain%2FConnectors%2FM365AdminAudit%2FAdminAudit.json
```
## Credit

Based on the [Microsoft 365 Audit General and DLP](https://github.com/Azure/Azure-Sentinel/tree/master/Solutions/Microsoft%20365%20Audit%20General%20and%20DLP) solution from the [Azure/Azure-Sentinel](https://github.com/Azure/Azure-Sentinel) repository.
