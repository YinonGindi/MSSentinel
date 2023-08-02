# Microsoft Sentinel All In One - PowerShell Version

<p align="center">
<img src="../Media/Sentinel All-in-One logo.jpg?raw=true">
</p>

Microsoft Sentinel All-in-One is aimed at helping customers and partners quickly set up a full-fledged Microsoft Sentinel environment that is ready to use, speeding up deployment and initial configuration tasks in few clicks, saving time and simplifying Microsoft Sentinel setup.


## What does All-in-One do?

Microsoft Sentinel All-in-One automates the following tasks:

- Creates resource group
- Creates Log Analytics workspace
- Installs Microsoft Sentinel on top of the workspace
- Sets workspace retention, daily cap and commitment tiers if desired
- Creates the **Azure Lighthouse** registration definition
- Creates the **Azure Lighthouse** registration assignments for BDOMDR to the resource group that will contain the Azure Sentinel resources
- Creates the SPN required by BDO MDR
- Assign the required permission to SPN

## Prerequisites

- Azure Subscription
- Azure user account with enough permissions to enable the desired connectors. See table at the end of this page for additional permissions. Write permissions to the workspace are **always** needed.
- Some data connectors require the relevant licence in order to be enabled. See table at the end of this page for details.


## Supported connectors

Due to recent Microsoft Sentinel changes, deploying Data Connector and Analytics rule are not supported

