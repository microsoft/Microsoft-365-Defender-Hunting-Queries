# Add uncommon credential type to application [Nobelium]

The query looks for users or service principals that attached an uncommon credential type to application.

As part of the Nobelium campaign, the attacker added credentials to already existing applications and used the application permissions to extract users' mails.

See [*How to: Use the portal to create an Azure AD application and service principal that can access resources*](https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal).

## Query

```Kusto
CloudAppEvents
| where Application == "Office 365"
| where ActionType in ("Add service principal credentials.", "Update application – Certificates and secrets management ")
| project Timestamp, RawEventData, AccountDisplayName, ActionType, AccountObjectId
| extend ModifiedProperties = RawEventData.ModifiedProperties[0]
| extend NewValue = ModifiedProperties.NewValue, OldValue = ModifiedProperties.OldValue, Name = ModifiedProperties.Name
| project Timestamp, AccountDisplayName, ActionType, NewValue, OldValue, RawEventData, AccountObjectId
| where (NewValue has "KeyType=Password" and OldValue !has "KeyType=Password" and OldValue has "AsymmetricX509Cert") or (NewValue has "AsymmetricX509Cert" and OldValue !has "AsymmetricX509Cert" and OldValue has "KeyType=Password")
| extend NewSecret = set_difference(todynamic(parse_json(tostring(NewValue))), todynamic(parse_json(tostring(OldValue))))
| project Timestamp,ActionType,ActorType = RawEventData.Actor[-1].ID, ObjectId = RawEventData.Actor[-2].ID, AccountDisplayName, AccountObjectId, AppnName = RawEventData.Target[3].ID, AppObjectId = RawEventData.Target[1].ID, NewSecret = NewSecret[0], RawEventData
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.
| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access |  |  |
| Execution |  |  |
| Persistence |  |  |
| Privilege escalation | V |  |
| Defense evasion |  |  |
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
* [ServicePrincipalAddedToRole [Nobelium]](./ServicePrincipalAddedToRole%20[Nobelium].md)

## Contributor info

**Contributor:** Dor Edry
**GitHub alias:** doredry
**Organization:** Microsoft 365 Defender
**Contact info:** dor.edry@microsoft.com
