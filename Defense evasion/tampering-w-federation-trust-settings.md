# Detect tampering with federation trust settings

This query was originally published in the threat analytics report, *Solorigate supply chain attack*.

Microsoft detects the [2020 SolarWinds supply chain attack](https://msrc-blog.microsoft.com/2020/12/13/customer-guidance-on-recent-nation-state-cyber-attacks/) implant and its other components as *Solorigate*. A threat actor silently added malicious code to legitimate software updates for Orion, which is IT monitoring software provided by SolarWinds. In this way, malicious dynamic link libraries (DLLs) were distributed to SolarWinds customers.

The following query detects when federation trust settings were changed for a domain. This method is not specific to just this threat actor or this attack.

More Solorigate-related queries can be found listed under the [See-also](#see-also) section of this document.

## Query

```kusto
let auditLookback = 1d;
CloudAppEvents
| where Timestamp > ago(auditLookback)
| where ActionType =~ "Set federation settings on domain."
| extend targetDetails = parse_json(ActivityObjects[1])
| extend targetDisplayName = targetDetails.Name
| extend resultStatus = extractjson("$.ResultStatus", tostring(RawEventData), typeof(string))
| project Timestamp, ActionType, InitiatingUserOrApp=AccountDisplayName, targetDisplayName, resultStatus, InitiatingIPAddress=IPAddress, UserAgent
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access |  |  |
| Execution |  |  |
| Persistence |  |  |
| Privilege escalation |  |  |
| Defense evasion | v |  |
| Credential Access |  |  |
| Discovery |  |  |
| Lateral movement |  |  |
| Collection |  |  |
| Command and control |  |  |
| Exfiltration |  |  |
| Impact |  |  |
| Vulnerability |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |

## See also

* [Credentials were added to an Azure AD application after 'Admin Consent' permissions granted [Solorigate]](../Persistence/CredentialsAddAfterAdminConsentedToApp[Solorigate].md)
* [Locate Solorigate-related malicious DLLs loaded in memory](../Campaigns/solorigate-locate-dll-loaded-in-memory.md)
* [Locate Solorigate-related malicious DLLs created in the system or locally](../Campaigns/solorigate-locate-dll-created-locally.md)
* [Locate SolarWinds processes launching suspicious PowerShell commands](../Campaigns/solorigate-launching-base64-powershell.md)
* [Locate SolarWinds processes launching command prompt with the echo command](../Campaigns/solorigate-launching-cmd-echo.md)
* [Locate Solorigate attempting DNS lookup of command-and-control infrastructure](../Campaigns/solorigate-c2-lookup-from-nonbrowser.md)
* [Get an inventory of SolarWinds Orion software possibly affected by Solorigate](../Campaigns/solorigate-possible-affected-software-orion.md)
* [Locate Solorigate receiving DNS response](../Campaigns/solorigate-c2-lookup-response.md)

## Contributor info

**Contributor:** Microsoft Threat Protection team
