# Mail.Read or Mail.ReadWrite permissions added to OAuth application

This query will find applications that have been granted Mail.Read or Mail.ReadWrite permissions in which the corresponding user recently consented to. It can help identify applications that have been abused to gain access to user email.

The actor, Nobelium, was observed modifying existing tenant application permissions to allow them to read user email through the Microsoft Graph API. See [*Customer Guidance on Recent Nation-State Cyber Attacks*](https://msrc-blog.microsoft.com/2020/12/13/customer-guidance-on-recent-nation-state-cyber-attacks/).

This query is insprired by an Azure Sentinel [detection](https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/MailPermissionsAddedToApplication.yaml).

## Query

```Kusto
let auditLookback = 1d;
CloudAppEvents
| where Timestamp > ago(auditLookback)
| where ActionType == "Add delegated permission grant."
| extend RawEventData = parse_json(RawEventData)
| where RawEventData.ResultStatus =~ "success"
| extend UserId = tostring(RawEventData.UserId)
| extend UserAgent = parse_json(replace('-','',tostring(RawEventData.ExtendedPRoperties[0].Value))).UserAgent
| extend properties = RawEventData.ModifiedProperties
| mvexpand properties
| extend Permissions = properties.NewValue
| where Permissions has_any ("Mail.Read", "Mail.ReadWrite")
| extend PermissionsAddedTo = tostring(RawEventData.Target[3].ID) // Get target of permissions
| project-away properties, RawEventData
| join kind=leftouter (CloudAppEvents
    | where Timestamp > ago(auditLookback)
    | where ActionType == "Consent to application."
    | where isnotempty(AccountDisplayName)
    | extend RawEventData = parse_json(RawEventData)
    | extend UserId = tostring(RawEventData.UserId)
    | extend targetInfo = RawEventData.Target
    | extend AppName = tostring(targetInfo[3].ID) // Find app name
    | extend AppId = tostring(targetInfo[4].ID) // Find appId
    | project ConsentTimestamp=Timestamp, UserId, AccountDisplayName, AppName, AppId
) on UserId
| extend ConsentTimestamp = todatetime(format_datetime(ConsentTimestamp, 'MM/dd/yyyy HH:mm')) // Ensure app consent happend close to the same time as the permissions were granted
| extend PermsTimestamp = todatetime(format_datetime(Timestamp, 'MM/dd/yyyy HH:mm'))
| where PermsTimestamp -2m <= ConsentTimestamp // ensure consent happened near permissions grant
| where PermsTimestamp +2m >= ConsentTimestamp
| project Timestamp, ActionType, InitiatingUser=AccountDisplayName, UserId, InitiatingIP=IPAddress, UserAgent, PermissionsAddedTo, AppName, AppId
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.
| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access |  |  |
| Execution |  |  |
| Persistence |  |  |
| Privilege escalation |  |  |
| Defense evasion | V |  |
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
* [Domain federation trust settings modified](./ADFSDomainTrustMods[Nobelium].md)
* [Discovering potentially tampered devices [Nobelium]](./Discovering%20potentially%20tampered%20devices%20[Nobelium].md)
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