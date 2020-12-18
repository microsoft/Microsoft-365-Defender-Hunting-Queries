# Locate SolarWinds processes launching suspicious PowerShell commands

This query was originally published in the threat analytics report, *Solorigate supply chain attack*.

Microsoft detects the [2020 SolarWinds supply chain attack](https://msrc-blog.microsoft.com/2020/12/13/customer-guidance-on-recent-nation-state-cyber-attacks/) implant and its other components as *Solorigate*. A threat actor silently added malicious code to legitimate software updates for Orion, which is IT monitoring software provided by SolarWinds. In this way, malicious dynamic link libraries (DLLs) were distributed to SolarWinds customers.

The following query detects events when SolarWinds processes launched PowerShell commands that were possibly encoded in Base64. Attackers may encode PowerShell commands in Base64 to obfuscate malicious activity.

More Solarigate-related queries can be found listed under the [See also](#see-also) section of this document.

## Query

```kusto
DeviceProcessEvents
| where InitiatingProcessFileName =~ "SolarWinds.BusinessLayerHost.exe"
| where FileName =~ "powershell.exe"
// Extract base64 encoded string, ensure valid base64 length
| extend base64_extracted = extract('([A-Za-z0-9+/]{20,}[=]{0,3})', 1, ProcessCommandLine)
| extend base64_extracted = substring(base64_extracted, 0, (strlen(base64_extracted) / 4) * 4)
| extend base64_decoded = replace(@'\0', '', make_string(base64_decode_toarray(base64_extracted)))
//
| where notempty(base64_extracted) and base64_extracted matches regex '[A-Z]' and base64_extracted matches regex '[0-9]'
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access |  |  |
| Execution | v |  |
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
* [Locate Solarigate-related malicious DLLs loaded in memory](locate-dll-loaded-in-memory[Solorigate].md)
* [Locate Solarigate-related malicious DLLs created in the system or locally](locate-dll-created-locally[Solorigate].md)
* [Locate SolarWinds processes launching command prompt with the echo command](launching-cmd-echo[Solorigate].md)
* [Locate Solarigate attempting DNS lookup of command-and-control infrastructure](c2-lookup-from-nonbrowser[Solorigate]..md)
* [Locate Solarigate receiving DNS response](c2-lookup-response[Solorigate].md)
* [Get an inventory of SolarWinds Orion software possibly affected by Solarigate](possible-affected-software-orion[Solorigate].md)
* [Detect tampering with federation trust settings](.\Defense%20evasion\tampering-w-federation-trust-settings[Solorigate].md)
* [Detect new access credentials added to app or service](../Privilege%20escalation/new-access-credential[Solorigate].md)

## Contributor info

**Contributor:** Microsoft Threat Protection team
