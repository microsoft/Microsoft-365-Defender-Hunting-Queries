# Locate SolarWinds processes launching suspicious PowerShell commands

This query was originally published in the threat analytics report, *Solorigate supply chain attack*. Please note that these attacks are currently known as the *Nobelium campaign*.

Microsoft detects the [2020 SolarWinds supply chain attack](https://msrc-blog.microsoft.com/2020/12/13/customer-guidance-on-recent-nation-state-cyber-attacks/) implant and its other components as part of a campaign by the Nobelium activity group. Nobelium is the threat actor behind the attack against SolarWinds, which was previously referred to as [*Solorigate*](https://www.microsoft.com/security/blog/2020/12/18/analyzing-solorigate-the-compromised-dll-file-that-started-a-sophisticated-cyberattack-and-how-microsoft-defender-helps-protect/).

Nobelium silently added malicious code to legitimate software updates for Orion, which is IT monitoring software provided by SolarWinds. In this way, malicious dynamic link libraries (DLLs) were distributed to SolarWinds customers.

The following query detects events when SolarWinds processes launched PowerShell commands that were possibly encoded in Base64. Attackers may encode PowerShell commands in Base64 to obfuscate malicious activity.

More Nobelium-related queries can be found listed under the [See also](#see-also) section of this document.

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

* [Locate Nobelium implant receiving DNS response](./c2-lookup-from-nonbrowser[Nobelium].md)
* [Locate Nobelium implant receiving DNS response](./c2-lookup-response[Nobelium].md)
* [Compromised certificate [Nobelium]](./compromised-certificate[Nobelium].md)
* [FireEye Red Team tool CVEs [Nobelium]](./fireeye-red-team-tools-CVEs%20[Nobelium].md)
* [FireEye Red Team tool HASHs [Nobelium]](./fireeye-red-team-tools-HASHs%20[Nobelium].md)
* [View data on software identified as affected by Nobelium campaign](./known-affected-software-orion[Nobelium].md)
* [Locate SolarWinds processes launching command prompt with the echo command](./launching-cmd-echo[Nobelium].md)
* [Locate Nobelium-related malicious DLLs created in the system or locally](./locate-dll-created-locally[Nobelium].md)
* [Locate Nobelium-related malicious DLLs loaded in memory](./locate-dll-loaded-in-memory[Nobelium].md)
* [Get an inventory of SolarWinds Orion software possibly affected by Nobelium](./possible-affected-software-orion[Nobelium].md)
* [Anomalous use of MailItemAccess on other users' mailboxes [Nobelium]](../Collection/Anomaly%20of%20MailItemAccess%20by%20Other%20Users%20Mailbox%20[Nobelium].md)
* [Nobelium campaign DNS pattern](../Command%20and%20Control/DNSPattern%20[Nobelium].md)
* [Nobelium encoded domain in URL](../Command%20and%20Control/EncodedDomainURL%20[Nobelium].md)
* [Domain federation trust settings modified](../Defense%20evasion/ADFSDomainTrustMods[Nobelium].md)
* [Discovering potentially tampered devices [Nobelium]](../Defense%20evasion/Discovering%20potentially%20tampered%20devices%20[Nobelium].md)
* [Mail.Read or Mail.ReadWrite permissions added to OAuth application](../Defense%20evasion/MailPermissionsAddedToApplication[Nobelium].md)
* [Suspicious enumeration using Adfind tool](../Discovery/SuspiciousEnumerationUsingAdfind[Nobelium].md)
* [Anomalous use of MailItemAccess by GraphAPI [Nobelium]](../Exfiltration/Anomaly%20of%20MailItemAccess%20by%20GraphAPI%20[Nobelium].md)
* [MailItemsAccessed throttling [Nobelium]](../Exfiltration/MailItemsAccessed%20Throttling%20[Nobelium].md)
* [OAuth apps accessing user mail via GraphAPI [Nobelium]](../Exfiltration/OAuth%20Apps%20accessing%20user%20mail%20via%20GraphAPI%20[Nobelium].md)
* [OAuth apps reading mail via GraphAPI and directly [Nobelium]](../Exfiltration/OAuth%20Apps%20reading%20mail%20both%20via%20GraphAPI%20and%20directly%20[Nobelium].md)
* [OAuth apps reading mail via GraphAPI anomaly [Nobelium]](../Exfiltration/OAuth%20Apps%20reading%20mail%20via%20GraphAPI%20anomaly%20[Nobelium].md)
* [Credentials were added to an Azure AD application after 'Admin Consent' permissions granted [Nobelium]](../Persistence/CredentialsAddAfterAdminConsentedToApp[Nobelium].md)
* [New access credential added to application or service principal](../Persistence/NewAppOrServicePrincipalCredential[Nobelium].md)
* [Add uncommon credential type to application [Nobelium]](../Privilege%20escalation/Add%20uncommon%20credential%20type%20to%20application%20[Nobelium].md)
* [ServicePrincipalAddedToRole [Nobelium]](../Privilege%20escalation/ServicePrincipalAddedToRole%20[Nobelium].md)

## Contributor info

**Contributor:** Microsoft Threat Protection team
