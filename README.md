
# Advanced hunting queries for Microsoft Threat Protection
This repo contains sample queries for [Advanced hunting](https://security.microsoft.com/hunting) in [Microsoft Threat Protection](https://aka.ms/mtp-docs).
With these sample queries, you can start to experience Advanced hunting, including the types of data that it covers and the query language it supports. You can also explore a variety of attack techniques and how they may be surfaced through Advanced hunting.

To get started, simply paste a sample query into the query builder and run the query. If you get syntax errors, try removing empty lines introduced when pasting. If a query returns no results, try expanding the time range. 

We are continually building up documentation about Advanced hunting and its data schema. You can access the full list of tables and columns in the portal or reference the following resources:

- [Advanced hunting overview](https://docs.microsoft.com/microsoft-365/security/mtp/advanced-hunting-overview)
- [Language overview](https://docs.microsoft.com/microsoft-365/security/mtp/advanced-hunting-query-language)
- [Schema tables descriptions](https://docs.microsoft.com/microsoft-365/security/mtp/advanced-hunting-schema-tables)
- [Kusto query language reference](https://docs.microsoft.com/azure/kusto/query/)

# Contributions

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## How to contribute

Everyone can freely add a file for a new query or improve on existing queries in the [queries folder](https://github.com/microsoft/MTP-AHQ/tree/master/queries). To help other users locate new queries quickly, we suggest that you:

- Create a new MarkDown file in the relevant folder according to the MITRE ATT&CK category with contents based on the [query submission template](https://github.com/microsoft/Microsoft-threat-protection-Hunting-Queries/blob/master/00-query-submission-template.md)   
- In the new file:
    - Provide a name for the query that represents the components or activities that it searches for, e.g. `Files from malicious sender` 
    - Describe the query and provide sufficient guidance when applicable
    - Select the categories that apply by marking the appropriate cell with a "v"
- Use the query name as the title, separating each word with a hyphen (-), e.g. `files-from-malicious-sender.md`
- Include comments that explain the attack technique or anomaly being hunted. Whenever possible, provide links to related documentation.

In addition, construct queries that adhere to the published [Microsoft Threat Protection Advanced hunting performance best practices](https://docs.microsoft.com/en-us/microsoft-365/security/mtp/advanced-hunting-best-practices?view=o365-worldwide).

# Suggestions and feedback
We maintain a backlog of suggested sample queries in the project [issues page](https://github.com/microsoft/Microsoft-threat-protection-Hunting-Queries/issues). Feel free to comment, rate, or provide suggestions.

We value your feedback. Let us know if you run into any problems or share your suggestions by sending email to wdatpqueriesfeedback@microsoft.com.
