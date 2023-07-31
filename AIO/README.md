# Microsoft Sentinel All In One - Free Tier

<p align="center">
<img src="./Media/Sentinel All-in-One logo.jpg?raw=true">
</p>

Microsoft Sentinel All-in-One is aimed at helping customers and partners quickly set up a full-fledged Microsoft Sentinel environment that is ready to use, speeding up deployment and initial configuration tasks in few clicks, saving time and simplifying Microsoft Sentinel setup.


## What does All-in-One do?

Microsoft Sentinel All-in-One automates the following tasks:

- Creates resource group
- Creates Log Analytics workspace
- Installs Microsoft Sentinel on top of the workspace
- Sets workspace retention, daily cap and commitment tiers if desired
- Installs Content Hub solutions from a predefined list in two categories: 1st party, Essentials
- Enables Free Data Connectors from this list:
    + Azure Active Directory Identity Protection
    + Azure Activity (from current subscription)
    + Microsoft 365 Defender (Microsoft Defender for Endpoint, Microsoft Defender for Identity, Microsoft Defender for Office, Microsoft Defender for Cloud Apps)
    + Microsoft Defender for Cloud
    + Microsoft Defender for IoT
    + Microsoft Insider Risk Management
    + Office 365
- Enables analytics rules (Scheduled and NRT) included in the selected Content Hub solutions, with the ability to filter by severity
- Enables analytics rules (Scheduled and NRT) that use any of the selected Data connectors, with the ability to filter by severity

## Prerequisites

- Azure Subscription
- Azure user account with enough permissions to enable the desired connectors. See table at the end of this page for additional permissions. Write permissions to the workspace are **always** needed.
- Some data connectors require the relevant licence in order to be enabled. See table at the end of this page for details.

## Try it now!

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https://raw.githubusercontent.com/YinonGindi/MSSentinel/main/AIO/azuredeploy.json/createUIDefinitionUri/https://raw.githubusercontent.com/YinonGindi/MSSentinel/main/AIO/createUiDefinition.json) 
 

## Supported connectors

The following table summarizes permissions, licenses and permissions needed and related cost to enable each Data Connector:

| Data Connector                                 | License         |  Permissions                    | Cost      |
| ---------------------------------------------- | --------------- |---------------------------------|-----------|
| Azure Active Directory Identity Protection  | AAD Premium 2   | Global Admin or Security Admin  | Free      |
| Azure Activity                                 | None            | Subscription Reader             | Free      |
| Microsoft 365 Defender                         | M365D license   | Global Admin or Security Admin  | Free      |
| Microsoft Defender for Cloud                   | MDC license     | Security Reader                 | Free      |
| Microsoft Defender for IoT                     | M4IOT license   | Security Reader                 | Free      |
| Microsoft Insider Risk Management              | IRM license     | Global Admin or Security Admin  | Free      |
| Office 365                                     | None            | Global Admin or Security Admin  | Free      |
