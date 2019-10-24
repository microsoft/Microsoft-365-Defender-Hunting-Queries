---
page_type: sample
languages:
- python
products:
- mdatp
description: "MDATP Advanced Hunting (AH) Sample Queries"
---

# About
This repo contains sample queries for [Advanced hunting](https://securitycenter.windows.com/hunting) on [Microsoft Defender Advanced Threat Protection](https://www.microsoft.com/en-us/windowsforbusiness/windows-atp?ocid=queryrepogit).
With these sample queries, you can start to experience Advanced hunting, including the types of data that it covers and the query language it supports. You can also explore a variety of attack techniques and how they may be surfaced through Advanced hunting.

To get started, simply paste a sample query into the query builder and run the query. If you get syntax errors, try removing empty lines introduced when pasting. If a query returns no results, try expanding the time range. 

We are continually building up documentation about Advanced hunting and its data schema. You can access the full list of tables and columns in the portal or reference the following resources:

- [Feature overview, tables, and common operators](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-atp/advanced-hunting-windows-defender-advanced-threat-protection)
- [Table columns and descriptions](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-atp/advanced-hunting-reference-windows-defender-advanced-threat-protection)
- [Query language reference](https://docs.microsoft.com/en-us/azure/kusto/query/)

*Not using Microsoft Defender ATP?* If you haven't yet, experience how you can effectively scale your organization's incident response capabilities by signing up for a [free Microsoft Defender ATP trial](https://www.microsoft.com/en-us/windowsforbusiness/windows-atp?ocid=queryrepogit). 

# Suggestions and feedback
We maintain a backlog of suggested sample queries in the project [issues page](https://github.com/Microsoft/WindowsDefenderATP-Hunting-Queries/issues). Feel free to comment, rate, or provide suggestions.

We value your feedback. Let us know if you run into any problems or share your suggestions by sending email to wdatpqueriesfeedback@microsoft.com.

# Contributions

<b>This project welcomes contributions and suggestions.</b>

Most contributions require you to agree to a Contributor License Agreement (CLA) declaring that you have the right to,
and actually do, grant us the rights to use your contribution. For details, visit
https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need
to provide a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the
instructions provided by the bot. You will only need to do this once across all repositories using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/)
or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

# Coding guidelines and references
The samples in this repo should include comments that explain the attack technique or anomaly being hunted. Whenever possible, provide links to related documentation.

In addition, construct queries that adhere to the published [Microsoft Defender ATP Advanced hunting performance best practices](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-atp/advanced-hunting-best-practices-windows-defender-advanced-threat-protection).
