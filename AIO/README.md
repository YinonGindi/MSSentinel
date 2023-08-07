# Microsoft Sentinel All In One - Free Tier

<p align="center">
<img src="./Media/Sentinel All-in-One logo.jpg?raw=true">
</p>


The overarching goal of Microsoft Sentinel All-in-One is to provide robust support for customers and partners by facilitating the seamless establishment of a comprehensive Microsoft Sentinel environment. This carefully curated solution is meticulously crafted to accelerate the deployment and initial configuration phases of Microsoft Sentinel, ensuring that the entire process can be accomplished with remarkable efficiency and minimal effort.

By offering a holistic approach to setting up Microsoft Sentinel, this innovative tool eliminates the need for arduous and time-consuming manual configurations. Instead, it offers a user-friendly experience that requires only a few clicks, making it an invaluable resource for expediting the implementation process. This, in turn, translates to a significant reduction in the time and resources typically invested in configuring Microsoft Sentinel.

The intricate complexities that often accompany the setup of advanced security solutions are effectively mitigated by the streamlined functionality of Microsoft Sentinel All-in-One. Its comprehensive framework not only expedites the deployment of Microsoft Sentinel but also ensures that the resulting environment is optimized for immediate utilization. This optimized environment, coupled with the simplified setup process, stands as a testament to Microsoft's commitment to empowering its customers and partners with tools that enhance operational efficiency while minimizing unnecessary intricacies.

In conclusion, Microsoft Sentinel All-in-One stands as a pivotal innovation in the realm of security solutions, aiming to revolutionize the way customers and partners interact with and implement Microsoft Sentinel. By providing a platform that not only accelerates deployment but also simplifies the initial configuration, Microsoft has taken a significant stride towards redefining the standards of convenience and effectiveness in setting up a robust security environment.

This is a special version of the Azure Sentinel All-In-One artifact that includes **Azure Lighthouse** delegation as part of the deployment.

## Prerequisites

- Azure Subscription
- Azure user account with enough permissions to enable the desired connectors. See table at the end of this page for additional permissions. Write permissions to the workspace are **always** needed.
- Some data connectors require the relevant licence in order to be enabled. See table at the end of this page for details.


## Supported connectors

The following table summarizes permissions, licenses and permissions needed and related cost to enable each Data Connector:

| Data Connector                                 | License         |  Permissions                    | Cost      |
| ---------------------------------------------- | --------------- |---------------------------------|-----------|
| Azure Active Directory Identity Protection  | AAD Premium 2   | Global Admin or Security Admin  | Free      |
| Azure Activity                                 | None            | Subscription Reader             | Free      |
| Microsoft 365 Defender                         | M365D license   | Global Admin or Security Admin  | Free      |
| Microsoft Defender for Cloud                   | MDC license     | Security Reader                 | Free      |
| Microsoft Insider Risk Management              | IRM license     | Global Admin or Security Admin  | Free      |
| Office 365                                     | None            | Global Admin or Security Admin  | Free      |




This repository was created based on <a href="https://github.com/Azure/Azure-Sentinel/tree/master/Tools/Sentinel-All-In-One">MS Sentinel AIO</a>
