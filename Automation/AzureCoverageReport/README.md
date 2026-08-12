# Azure Coverage Report – Logic App

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FYinonGindi%2FMicrosoft_Sentinel%2Fmain%2FAutomation%2FAzureCoverageReport%2Fazuredeploy.json)

## Overview

This Logic App reports how well your Azure estate is covered by monitoring and security tooling, then emails the result on a schedule (default: monthly).

It answers three questions:

1. **Which resources send diagnostic logs to a Microsoft Sentinel workspace?**
2. **Which resources send diagnostic logs to a Log Analytics workspace that is *not* Sentinel-enabled?**
3. **How many Microsoft Defender for Cloud plans are enabled across your subscriptions?**

Every resource in scope is classified into one of five states:

| Status | Meaning |
|---|---|
| `Sentinel` | Diagnostic settings point at a Sentinel-enabled workspace |
| `Monitored` | Diagnostic settings point at a Log Analytics workspace without Sentinel |
| `Other` | Diagnostic settings exist, but target a non-workspace sink (Event Hub, Storage) |
| `Not Monitored` | No diagnostic settings configured |
| `Error` | The diagnostic settings API call failed for that resource |

The report is delivered as an HTML email with two attachments: `Coverage.csv` (the full per-resource inventory) and `mdc.html` (a Defender for Cloud plan breakdown).

## How It Works

```
┌──────────────────────────┐
│  Recurrence Trigger       │  (default: monthly)
└────────────┬─────────────┘
             ▼
┌──────────────────────────┐
│  Initialize variables     │──► Settings, StartTime, SkipToken, Resources
└────────────┬─────────────┘
             │
      ┌──────┴───────────────────────────┐   (parallel scopes)
      ▼                                  ▼
┌───────────────────────┐      ┌──────────────────────────┐
│  Sentinel_Coverage     │      │  MDC_Coverage             │
├───────────────────────┤      ├──────────────────────────┤
│ Get Sentinel workspaces│      │ Query securityresources  │
│ (SecurityInsights KQL) │      │ for 11 Defender plans    │
│           │            │      │           │              │
│           ▼            │      │           ▼              │
│ ┌────────────────────┐ │      │ ┌──────────────────────┐ │
│ │ Until loop:        │ │      │ │ Compose MDC HTML     │ │
│ │ Resource Graph +   │ │      │ │ bar-chart report     │ │
│ │ $skipToken paging  │ │      │ └──────────────────────┘ │
│ └─────────┬──────────┘ │      └────────────┬─────────────┘
│           ▼            │                   │
│ ┌────────────────────┐ │                   │
│ │ For each resource: │ │                   │
│ │  GET diagnostic    │ │                   │
│ │  settings          │ │                   │
│ │  → classify Status │ │                   │
│ │  (concurrency 50)  │ │                   │
│ └─────────┬──────────┘ │                   │
│           ▼            │                   │
│ ┌────────────────────┐ │                   │
│ │ Create CSV table   │ │                   │
│ │ Filter: Sentinel   │ │                   │
│ │ Filter: LAW        │ │                   │
│ └────────────────────┘ │                   │
└───────────┬───────────┘                   │
            └───────────────┬────────────────┘
                            ▼
              ┌───────────────────────────┐
              │  Send an email (V2)        │
              │  HTML summary +            │
              │  Coverage.csv + mdc.html   │
              └───────────────────────────┘
```

### Resource Graph pagination

Resource Graph returns at most 1,000 rows per call. The `Until` loop repeatedly calls the API with the returned `$skipToken`, merging each page into the `Resources` variable, until no token is returned. The loop is capped at **60 iterations** with a **1-hour timeout** — roughly 60,000 resources.

## Prerequisites

1. An Azure subscription with permission to deploy resources and to create role assignments
2. An Office 365 / Exchange Online mailbox that can be used to send the report
3. Resources with **diagnostic settings** configured, so there is something to measure

## Deployment Parameters

| Parameter | Required | Default | Description |
|---|---|---|---|
| `logicAppName` | | `Sentinel-AzureCoverageReport` | Name of the Logic App resource |
| `location` | | Resource group location | Azure region for the Logic App and API connection |
| `recipientEmail` | ✅ | — | Email address that receives the coverage report |
| `emailSubject` | | `Azure Coverage Report` | Subject line of the report email |
| `office365ConnectionName` | | `office365-coveragereport` | Name of the Office 365 API connection |
| `recurrenceFrequency` | | `Month` | How often the report runs (`Day`, `Week`, `Month`) |
| `recurrenceInterval` | | `1` | Number of frequency units between runs |
| `recurrenceTimeZone` | | `UTC` | Time zone used to evaluate the schedule |
| `recurrenceStartTime` | | `2026-01-01T06:00:00` | First scheduled run (`yyyy-MM-ddTHH:mm:ss`) |
| `subscriptionIds` | | `[]` | Subscriptions to report on. Empty = every subscription the identity can read |
| `resourceTypes` | | 29 common types | Resource types included in the diagnostic-settings check |
| `logicAppState` | | `Disabled` | Deploy the Logic App enabled or disabled |

### Default resource types

The template ships with 29 resource types that support diagnostic settings, including API Management, Automation Accounts, Redis, Cognitive Services, Virtual Machines, Container Registries, AKS, MariaDB/MySQL/PostgreSQL, Cosmos DB, Data Collection Rules, Key Vaults, Logic Apps, Machine Learning, Application Gateways, Azure Firewall, Bastion, DDoS plans, Front Door, NSGs, Recovery Services Vaults, SQL, SQL VMs, Storage Accounts, Synapse, and App Service.

Override `resourceTypes` to narrow or widen the scope. Values must be lowercase Resource Graph type strings, e.g. `microsoft.compute/virtualmachines`.

## What Gets Deployed

| Resource | Type | Purpose |
|---|---|---|
| Logic App | `Microsoft.Logic/workflows` | The reporting workflow, with a system-assigned managed identity |
| API Connection | `Microsoft.Web/connections` | Office 365 connector used to send the email |

> No role assignments are created by this template — see below.

## Post-Deployment

> **Important:** The Logic App is deployed in a **Disabled** state. Complete both steps below, then enable it.

### 1. Authorize the Office 365 connection

The API connection is created but not authenticated. In the Azure portal, open the connection (name from the `office365ConnectionName` output), select **Edit API connection**, and click **Authorize** with the mailbox that should send the report. Save.

### 2. Assign roles to the managed identity

The workflow reads Resource Graph, diagnostic settings, and Defender for Cloud pricing. Grant the Logic App's system-assigned identity the following at the **subscription** or **management group** scope you want reported:

| Role | Why |
|---|---|
| `Reader` | Resource Graph queries and `Microsoft.Insights/diagnosticSettings/read` |
| `Security Reader` | The `securityresources` / `Microsoft.Security/pricings` query |

Take `managedIdentityPrincipalId` from the deployment outputs, then:

```bash
# Subscription scope
az role assignment create \
  --assignee "<managed-identity-principal-id>" \
  --role "Reader" \
  --scope "/subscriptions/<sub>"

az role assignment create \
  --assignee "<managed-identity-principal-id>" \
  --role "Security Reader" \
  --scope "/subscriptions/<sub>"
```

```bash
# Management group scope (recommended for multi-subscription reporting)
az role assignment create \
  --assignee "<managed-identity-principal-id>" \
  --role "Reader" \
  --scope "/providers/Microsoft.Management/managementGroups/<mg-id>"

az role assignment create \
  --assignee "<managed-identity-principal-id>" \
  --role "Security Reader" \
  --scope "/providers/Microsoft.Management/managementGroups/<mg-id>"
```

Role assignments can take a few minutes to propagate.

### 3. Enable the Logic App

```bash
az logic workflow update \
  --resource-group "<rg>" \
  --name "<logic-app-name>" \
  --state Enabled
```

Then use **Run Trigger** in the portal to confirm the first report arrives.

## Notes

- **Identity:** the workflow authenticates to `https://management.azure.com` with its **system-assigned managed identity**. No user-assigned identity or app registration is required.
- **Scope:** leaving `subscriptionIds` empty makes Resource Graph query every subscription the managed identity can read. This is usually what you want; set it explicitly to report on a subset.
- **Sentinel detection:** a workspace is treated as Sentinel-enabled when a `microsoft.operationsmanagement/solutions` resource named `SecurityInsights(<workspace>)` exists. A resource is marked `Sentinel` when any of its diagnostic settings target one of those workspaces.
- **Concurrency:** the per-resource loop runs 50 iterations in parallel. Lower this in the designer if you hit API throttling on very large estates.
- **Failure tolerance:** `Get_Settings` is allowed to fail per resource (`runAfter` accepts `Succeeded` and `Failed`); those resources are reported as `Error` rather than failing the run.
- **Empty results:** the percentages in the email divide by the resource and subscription counts. If a query returns nothing — for example, the role assignment has not propagated yet — the email action will fail on a division by zero. Verify roles before enabling.
- **Percentage baseline:** the headline percentages divide by `totalRecords` from the **last** Resource Graph page rather than the accumulated total. On estates small enough to fit in a single page (under 1,000 resources) this is exact; above that the percentages read high. The CSV attachment is always complete and authoritative.
- **Runtime:** the email includes an elapsed-time footer calculated from the `StartTime` variable.

## Deployment Outputs

| Output | Description |
|---|---|
| `logicAppName` | Name of the deployed Logic App |
| `managedIdentityPrincipalId` | Principal ID of the system-assigned identity (use for role assignments) |
| `office365ConnectionName` | Name of the Office 365 API connection that needs authorizing |
