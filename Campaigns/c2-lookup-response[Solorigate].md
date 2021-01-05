# Locate Solorigate receiving DNS response

This query was originally published in the threat analytics report, *Solorigate supply chain attack*.

Microsoft detects the [2020 SolarWinds supply chain attack](https://msrc-blog.microsoft.com/2020/12/13/customer-guidance-on-recent-nation-state-cyber-attacks/) implant and its other components as *Solorigate*. A threat actor silently added malicious code to legitimate software updates for Orion, which is IT monitoring software provided by SolarWinds. In this way, malicious dynamic link libraries (DLLs) were distributed to SolarWinds customers.

The following query detects events when Solorigate received a DNS response after launching a lookup request to known command-and-control infrastructure.

More Solorigate-related queries can be found listed under the [See also](#see-also) section of this document.

## Query

```kusto
DeviceEvents
| where ActionType == "DnsQueryResponse" //DNS Query Response
and AdditionalFields has ".avsvmcloud"
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
| Command and control | v |  |
| Exfiltration |  |  |
| Impact |  |  |
| Vulnerability |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |

## See also

* [Credentials were added to an Azure AD application after 'Admin Consent' permissions granted [Solorigate]](../Persistence/CredentialsAddAfterAdminConsentedToApp[Solorigate].md)
* [Locate Solorigate-related malicious DLLs loaded in memory](locate-dll-loaded-in-memory[Solorigate].md)
* [Locate Solorigate-related malicious DLLs created in the system or locally](locate-dll-created-locally[Solorigate].md)
* [Locate SolarWinds processes launching suspicious PowerShell commands](launching-base64-powershell[Solorigate].md)
* [Locate SolarWinds processes launching command prompt with the echo command](launching-cmd-echo[Solorigate].md)
* [Locate Solorigate attempting DNS lookup of command-and-control infrastructure](c2-lookup-from-nonbrowser[Solorigate]..md)
* [Get an inventory of SolarWinds Orion software possibly affected by Solorigate](possible-affected-software-orion[Solorigate].md)
* [View data on software identified as affected by Solorigate](known-affected-software-orion[Solorigate].md)

## Contributor info

**Contributor:** Microsoft Threat Protection team
