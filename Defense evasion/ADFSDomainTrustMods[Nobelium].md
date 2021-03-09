# Domain federation trust settings modified

This query will find when federation trust settings are changed for a domain or when the domain is changed from managed to federated authentication. Results will relate to when a new Active Directory Federated Service (ADFS) TrustedRealm object, such as a signing certificate, is added.

Modification to domain federation settings should be rare, so confirm the added or modified target domain/URL is legitimate administrative behavior.

The actor, Nobelium, was observed modifying domain trust settings to subvert existing mechanisms and cause the domain to accept authorization tokens signed with actor-owned certificates. See [*Customer Guidance on Recent Nation-State Cyber Attacks*](https://msrc-blog.microsoft.com/2020/12/13/customer-guidance-on-recent-nation-state-cyber-attacks/).

To understand why an authorized user may update settings for a federated domain in Office 365, Azure, or Intune, see [*Update or repair the settings of a federated domain in Office 365, Azure, or Intune*](https://docs.microsoft.com/office365/troubleshoot/active-directory/update-federated-domain-office-365).

For details on security realms that accept security tokens, see the ADFS Proxy Protocol (MS-ADFSPP) specification: [*3.2.5.1.2.4 Security Realm Data*](https://docs.microsoft.com/openspecs/windows_protocols/ms-adfspp/e7b9ea73-1980-4318-96a6-da559486664b).

For further information on AuditLogs, please see [*Azure AD audit activity reference*](https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities).

This query is inspired by an Azure Sentinal [detection](https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/ADFSDomainTrustMods.yaml).

## Query

```Kusto
let auditLookback = 1d;
(union isfuzzy=true 
    (
    CloudAppEvents
    | where Timestamp > ago(auditLookback)
    | where ActionType =~ "Set federation settings on domain."
    ),
    (
    CloudAppEvents
    | where Timestamp > ago(auditLookback)
    | where ActionType =~ "Set domain authentication."
    | extend modifiedProperties = parse_json(RawEventData).ModifiedProperties
    | mvexpand modifiedProperties
    | extend newDomainValue=tostring(parse_json(modifiedProperties).NewValue)
    | where newDomainValue has "Federated"
    )
)
| extend resultStatus = extractjson("$.ResultStatus", tostring(RawEventData), typeof(string))
| extend targetDisplayName = parse_json(RawEventData).Target[0].ID
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
| Defense evasion | V | T1484.002 |
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

* [Locate Nobelium implant receiving DNS response](../Campaigns/c2-lookup-from-nonbrowser[Nobelium].md)
* [Locate Nobelium implant receiving DNS response](../Campaigns/c2-lookup-response[Nobelium].md)
* [Compromised certificate [Nobelium]](../Campaigns/compromised-certificate[Nobelium].md)
* [FireEye Red Team tool CVEs [Nobelium]](../Campaigns/fireeye-red-team-tools-CVEs%20[Nobelium].md)
* [FireEye Red Team tool HASHs [Nobelium]](../Campaigns/fireeye-red-team-tools-HASHs%20[Nobelium].md)
* [View data on software identified as affected by Nobelium campaign](../Campaigns/known-affected-software-orion[Nobelium].md)
* [Locate SolarWinds processes launching suspicious PowerShell commands](../Campaigns/launching-base64-powershell[Nobelium].md)
* [Locate SolarWinds processes launching command prompt with the echo command](../Campaigns/launching-cmd-echo[Nobelium].md)
* [Locate Nobelium-related malicious DLLs created in the system or locally](../Campaigns/locate-dll-created-locally[Nobelium].md)
* [Locate Nobelium-related malicious DLLs loaded in memory](../Campaigns/locate-dll-loaded-in-memory[Nobelium].md)
* [Get an inventory of SolarWinds Orion software possibly affected by Nobelium](../Campaigns/possible-affected-software-orion[Nobelium].md)
* [Anomalous use of MailItemAccess on other users' mailboxes [Nobelium]](../Collection/Anomaly%20of%20MailItemAccess%20by%20Other%20Users%20Mailbox%20[Nobelium].md)
* [Nobelium campaign DNS pattern](../Command%20and%20Control/DNSPattern%20[Nobelium].md)
* [Nobelium encoded domain in URL](../Command%20and%20Control/EncodedDomainURL%20[Nobelium].md)
* [Discovering potentially tampered devices [Nobelium]](./Discovering%20potentially%20tampered%20devices%20[Nobelium].md)
* [Mail.Read or Mail.ReadWrite permissions added to OAuth application](./MailPermissionsAddedToApplication[Nobelium].md)
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

**Contributor:** Blake Strom
**GitHub alias:** @bstrom
**Organization:** Microsoft 365 Defender
**Contact info:** blstrom@microsoft.com