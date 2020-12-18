# Get an inventory of SolarWinds Orion software possibly affected by Solarigate

This query was originally published in the threat analytics report, *Solorigate supply chain attack*.

Microsoft detects the [2020 SolarWinds supply chain attack](https://msrc-blog.microsoft.com/2020/12/13/customer-guidance-on-recent-nation-state-cyber-attacks/) implant and its other components as *Solorigate*. A threat actor silently added malicious code to legitimate software updates for Orion, which is IT monitoring software provided by SolarWinds. In this way, malicious dynamic link libraries (DLLs) were distributed to SolarWinds customers.

The following query retrieves an inventory of SolarWinds Orion software use in your organization, organized by product name and ordered by how many devices the software is installed on.

More Solarigate-related queries can be found listed under the [See also](#see-also) section of this document.

## Query

```kusto
DeviceTvmSoftwareInventoryVulnerabilities
| where SoftwareVendor == 'solarwinds'
| where SoftwareName startswith 'orion'
| summarize dcount(DeviceName) by SoftwareName
| sort by dcount_DeviceName desc
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access |  |  |
| Execution |  |  |
| Persistence |  |  |
| Privilege escalation |  |  |
| Defense evasion |  |  |
| Credential Access |  |  |
| Discovery |  |  |
| Lateral movement |  |  |
| Collection |  |  |
| Command and control |  |  |
| Exfiltration |  |  |
| Impact | v | Not all instances of SolarWinds Orion may be affected by Solarigate. |
| Vulnerability |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |

## See also

* [Credentials were added to an Azure AD application after 'Admin Consent' permissions granted [Solorigate]](../Persistence/CredentialsAddAfterAdminConsentedToApp[Solorigate].md)
* [Locate Solarigate-related malicious DLLs loaded in memory](locate-dll-loaded-in-memory[Solorigate].md)
* [Locate Solarigate-related malicious DLLs created in the system or locally](locate-dll-created-locally[Solorigate].md)
* [Locate SolarWinds processes launching suspicious PowerShell commands](launching-base64-powershell[Solorigate].md)
* [Locate SolarWinds processes launching command prompt with the echo command](launching-cmd-echo[Solorigate].md)
* [Locate Solarigate attempting DNS lookup of command-and-control infrastructure](c2-lookup-from-nonbrowser[Solorigate]..md)
* [Locate Solarigate receiving DNS response](c2-lookup-response[Solorigate].md)
* [Detect tampering with federation trust settings](../Defense%20evasion/tampering-w-federation-trust-settings[Solorigate].md)
* [Detect new access credentials added to app or service](../Privilege%20escalation/new-access-credential[Solorigate].md)


## Contributor info

**Contributor:** Microsoft Threat Protection team
