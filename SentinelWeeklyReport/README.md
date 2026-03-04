# ARM Template: Sentinel Weekly Report — Logic App + Managed Identity + Automation Account

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FYinonGindi%2FMSSentinel%2Fmain%2FSentinelWeeklyReport%2Fazuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2FYinonGindi%2FMSSentinel%2Fmain%2FSentinelWeeklyReport%2FcreateUiDefinition.json)

Deploys the full **Microsoft Sentinel Weekly Report** infrastructure via a single ARM template.

## What It Deploys

| Resource | Type | Details |
|----------|------|---------|
| **User-Assigned Managed Identity** | `Microsoft.ManagedIdentity/userAssignedIdentities` | Shared identity for Logic App and Automation Account |
| **Sentinel Reader Role Assignment** | `Microsoft.Authorization/roleAssignments` | Assigns Microsoft Sentinel Reader to the managed identity on the workspace |
| **Automation Account** | `Microsoft.Automation/automationAccounts` | Basic SKU, runs PowerShell runbook |
| **Runbook — Get-SentinelContentUpdates** | `Microsoft.Automation/automationAccounts/runbooks` | Checks Sentinel Content Hub for solution updates |
| **API Connection — Azure Automation** | `Microsoft.Web/connections` | Managed identity auth |
| **API Connection — Azure Monitor Logs** | `Microsoft.Web/connections` | Managed identity auth |
| **API Connection — Office 365** | `Microsoft.Web/connections` | For sending email reports |
| **Logic App (Consumption)** | `Microsoft.Logic/workflows` | Weekly Sentinel ingestion report |

## Logic App Workflow

The Logic App runs weekly (configurable) and:

1. **Triggers** on a recurrence schedule (default: every 7 days at 10:30 Israel Standard Time)
2. **Starts an Automation Account runbook** (PowerShell) to get Sentinel Content Hub updates
3. **Queries Log Analytics** for weekly ingestion data (current vs previous week comparison)
4. **Builds an HTML report** with ingestion table and change percentages
5. **Waits 150 seconds** for the runbook to complete
6. **Sends an email** via Office 365 with the combined Sentinel Weekly Report

## Prerequisites

- Azure subscription with Contributor access
- [Azure PowerShell module](https://learn.microsoft.com/en-us/powershell/azure/install-azure-powershell) or [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli)
- The PowerShell runbook must already exist in the Automation Account (or be imported after deployment)
- Office 365 connection requires manual authorization after deployment (OAuth consent)

## Files

| File | Description |
|------|-------------|
| `azuredeploy.json` | Main ARM template with all resources |
| `azuredeploy.parameters.json` | Parameters file — **edit resource names here** |
| `createUiDefinition.json` | Azure Portal UI definition — dropdowns for resource groups & workspaces |
| `deploy.ps1` | PowerShell deployment script |
| `Get-SentinelContentUpdates.ps1` | Runbook source — Sentinel Content Hub update checker |

## Deployment

### Option 1: Deploy to Azure Button

Click the **Deploy to Azure** button at the top of this README. It opens the Azure Portal with the template pre-loaded — just fill in the parameters and deploy.

### Option 2: Azure CLI (from repo URL)

```bash
az deployment group create \
  --resource-group Sentinel-ContentUpdates_group \
  --template-uri https://raw.githubusercontent.com/YinonGindi/MSSentinel/main/SentinelWeeklyReport/azuredeploy.json \
  --parameters @azuredeploy.parameters.json
```

### Option 3: PowerShell Script (local clone)

```powershell
git clone https://github.com/YinonGindi/MSSentinel.git
cd MSSentinel\SentinelWeeklyReport
.\deploy.ps1 -ResourceGroupName "Sentinel-ContentUpdates_group" -Location "israelcentral"
```

### Option 4: Azure PowerShell (from repo URL)

```powershell
New-AzResourceGroupDeployment `
  -ResourceGroupName "Sentinel-ContentUpdates_group" `
  -TemplateUri "https://raw.githubusercontent.com/YinonGindi/MSSentinel/main/SentinelWeeklyReport/azuredeploy.json" `
  -TemplateParameterFile "azuredeploy.parameters.json"
```

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `location` | string | Resource group location | Azure region for all resources |
| `managedIdentityName` | string | *(required)* | Name of the User-Assigned Managed Identity |
| `managedIdentityResourceGroup` | string | Deployment RG | RG containing the managed identity |
| `logicAppName` | string | *(required)* | Name of the Logic App |
| `automationAccountName` | string | *(required)* | Name of the Automation Account |
| `automationAccountResourceGroup` | string | Deployment RG | RG of the Automation Account |
| `runbookName` | string | `Get-SentinelContentUpdates` | Name of the PowerShell runbook to execute |
| `subscriptionId` | string | Current subscription | Azure Subscription ID |
| `sentinelResourceGroup` | string | *(required)* | RG containing the Log Analytics workspace |
| `workspaceName` | string | *(required)* | Log Analytics workspace name |
| `emailRecipient` | string | *(required)* | Email address for the weekly report |
| `connectionsResourceGroup` | string | Deployment RG | RG for the API connections |
| `_artifactsLocation` | string | Template link URI | Base URL for repo files (auto-resolved when deploying via URL) |
| `recurrenceIntervalDays` | int | `7` | How often the Logic App runs (days) |
| `recurrenceHour` | int | `10` | Hour of day to run (0-23) |
| `recurrenceMinute` | int | `30` | Minute of hour to run (0-59) |
| `timeZone` | string | `Israel Standard Time` | Time zone for the schedule |

## Outputs

| Output | Description |
|--------|-------------|
| `managedIdentityPrincipalId` | Use this to assign RBAC roles (e.g., Log Analytics Reader) |
| `managedIdentityClientId` | Client ID for the managed identity |
| `logicAppId` | Resource ID of the deployed Logic App |
| `automationAccountId` | Resource ID of the deployed Automation Account |

## Runbook: Get-SentinelContentUpdates.ps1

The `Get-SentinelContentUpdates` runbook connects via managed identity and:

1. Queries the Sentinel Content Hub API for **installed** content packages
2. Queries for **available** content packages
3. Compares versions to find solutions needing updates
4. Generates an HTML report with a table of outdated solutions

The runbook is **automatically deployed** from this repo via `publishContentLink` — no manual import needed when deploying from the public repo URL.

## Post-Deployment Steps

1. **Authorize the Office 365 connection** — Open the `office365` API connection in the Azure Portal → Edit API Connection → Authorize → Save
2. **Assign additional RBAC roles** to the managed identity (Sentinel Reader is assigned automatically):
   - `Log Analytics Reader` on the workspace
   - `Automation Job Operator` on the Automation Account
3. **Test** by triggering the Logic App manually from the Azure Portal
