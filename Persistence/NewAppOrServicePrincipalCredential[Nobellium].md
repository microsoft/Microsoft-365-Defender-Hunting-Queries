# New access credential added to Application or Service principal

This query will find when a new credential is added to an application or service principal.

The Nobelium activity group was able to gain sufficient access to add credentials to existing applications with mail read permissions. They used that access to exfiltrate email.

See [*Customer Guidance on Recent Nation-State Cyber Attacks*](https://msrc-blog.microsoft.com/2020/12/13/customer-guidance-on-recent-nation-state-cyber-attacks/) for more on the Nobelium campaign (formerly known as Solorigate).

Additional information on OAuth Credential Grants can be found in RFC 6749 Section 4.4 or [*Azure AD audit activity reference*](https://docs.microsoft.com/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow).

For further information on AuditLogs please see [*Azure AD audit activity reference*](https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities).

This query was inspired by an Azure Sentinel [detection](https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/NewAppOrServicePrincipalCredential.yaml).

## Query

```kusto
// New access credential added to application or service principal
let auditLookback = 1d;
CloudAppEvents
| where Timestamp > ago(auditLookback)
| where ActionType in ("Add service principal.", "Add service principal credentials.", "Update application � Certificates and secrets management ")
| extend RawEventData = parse_json(RawEventData)
| where RawEventData.ResultStatus =~ "success"
// Select only users or applications initiating the credential changes
| extend ActorDetails = RawEventData.Actor
| mvexpand ActorDetails
| where ActorDetails has "@"
| extend targetDetails = parse_json(ActivityObjects[1])
| extend targetId = targetDetails.Id
| extend targetType = targetDetails.Type
| extend targetDisplayName = targetDetails.Name
| extend keyEvents = RawEventData.ModifiedProperties
| where keyEvents has "KeyIdentifier=" and keyEvents has "KeyUsage=Verify"
| mvexpand keyEvents
| where keyEvents.Name =~ "KeyDescription"
| parse keyEvents.NewValue with * "KeyIdentifier=" keyIdentifier:string ",KeyType=" keyType:string ",KeyUsage=" keyUsage:string ",DisplayName=" keyDisplayName:string "]" *
| parse keyEvents.OldValue with * "KeyIdentifier=" keyIdentifierOld:string ",KeyType" *
| where keyEvents.OldValue == "[]" or keyIdentifier != keyIdentifierOld
| where keyUsage == "Verify"
| project-away keyEvents
| project Timestamp, ActionType, InitiatingUserOrApp=AccountDisplayName, InitiatingIPAddress=IPAddress, UserAgent, targetDisplayName, targetId, targetType, keyDisplayName, keyType, keyUsage, keyIdentifier
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.
| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access |  |  |
| Execution |  |  |
| Persistence | V | T1098.001 |
| Privilege escalation |  |  |
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

## Contributor info

**Contributor:** Blake Strom
**GitHub alias:** @bstrom
**Organization:** Microsoft 365 Defender
**Contact info:** blstrom@microsoft.com
