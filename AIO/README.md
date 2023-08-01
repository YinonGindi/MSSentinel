# Microsoft Sentinel All In One - Basic Tier

<p align="center">
<img src="./Media/Sentinel All-in-One logo.jpg?raw=true">
</p>

Microsoft Sentinel All-in-One is aimed at helping customers and partners quickly set up a full-fledged Microsoft Sentinel environment that is ready to use, speeding up deployment and initial configuration tasks in few clicks, saving time and simplifying Microsoft Sentinel setup.


## What does All-in-One do?

Microsoft Sentinel All-in-One automates the following tasks:

- Creates resource group
- Creates the **Azure Lighthouse** registration definition
- Creates the **Azure Lighthouse** registration assignments for BDOMDR to the resource group that will contain the Azure Sentinel resources
- Creates Log Analytics workspace
- Installs Microsoft Sentinel on top of the workspace
- Sets workspace retention, daily cap and commitment tiers if desired
- Enables Free Data Connectors from this list:
    + Microsoft Entra ID (Azure Active Directory)*
    + Azure Activity (from current subscription)
    + Microsoft 365 Defender (Microsoft Defender for Endpoint, Microsoft Defender for Identity, Microsoft Defender for Office, Microsoft Defender for Cloud Apps)
    + Microsoft Defender for Cloud (Azure Security Center)
    + Microsoft Defender for IoT
    + Microsoft Entra ID Identity Protection (Azure Active Directory Identity Protection)
    + Microsoft Insider Risk Management
    + Office 365
- Enables analytics rules (Scheduled and NRT) that use any of the selected Data connectors, with the ability to filter by severity

*Microsoft 365 E5, A5, F5 and G5 and Microsoft 365 E5, A5, F5 and G5 Security customers can receive a data grant of up to 5MB per user/day to ingest Microsoft 365 data.
The data sources included in this offer include:
   + Azure Active Directory (Azure AD) sign-in and audit logs
   + Microsoft Information Protection logs
   + Microsoft 365 advanced hunting data

## Prerequisites

- Azure Subscription
- Azure user account with enough permissions to enable the desired connectors. See table at the end of this page for additional permissions. Write permissions to the workspace are **always** needed.
- Some data connectors require the relevant licence in order to be enabled. See table at the end of this page for details.

## Try it now!
<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FYinonGindi%2FMSSentinel%2Fmain%2FAIO%2Fazuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2FYinonGindi%2FMSSentinel%2Fmain%2FAIO%2FcreateUiDefinition.json"><p align="center"><img src="https://aka.ms/deploytoazurebutton"></p></a>

## Supported connectors

The following table summarizes permissions, licenses and permissions needed and related cost to enable each Data Connector:

| Data Connector                                 | License         |  Permissions                    | Cost      |
| ---------------------------------------------- | --------------- |---------------------------------|-----------|
| Azure Active Directory (Tenant scope version only) | Any AAD license | Global Admin or Security Admin  | Billed    |
| Azure Active Directory Identity Protection  | AAD Premium 2   | Global Admin or Security Admin  | Free      |
| Azure Activity                                 | None            | Subscription Reader             | Free      |
| Microsoft 365 Defender                         | M365D license   | Global Admin or Security Admin  | Free      |
| Microsoft Defender for Cloud                   | MDC license     | Security Reader                 | Free      |
| Microsoft Insider Risk Management              | IRM license     | Global Admin or Security Admin  | Free      |
| Office 365                                     | None            | Global Admin or Security Admin  | Free      |




This repository was created based on <a href="https://github.com/Azure/Azure-Sentinel/tree/master/Tools/Sentinel-All-In-One">MS Sentinel AIO</a>
