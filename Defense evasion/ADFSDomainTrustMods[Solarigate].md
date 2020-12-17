# Domain federation trust settings modified
This query will find when federation trust settings are changed for a domain. Results will relate to when a new Active Directory Federated Service (ADFS) TrustedRealm object, such as a signing certificate, is added. 
Modification to domain federation settings should be rare, so confirm the added or modified target domain/URL is legitimate administrative behavior.

Solarigate - The actor was observed modifying domain trust settings to subvert existing mechanisms and cause the domain to accept authorization tokens signed with actor-owned certificates. https://msrc-blog.microsoft.com/2020/12/13/customer-guidance-on-recent-nation-state-cyber-attacks/

To understand why an authorized user may update settings for a federated domain in Office 365, Azure, or Intune, see: https://docs.microsoft.com/office365/troubleshoot/active-directory/update-federated-domain-office-365.
For details on security realms that accept security tokens, see the ADFS Proxy Protocol (MS-ADFSPP) specification: https://docs.microsoft.com/openspecs/windows_protocols/ms-adfspp/e7b9ea73-1980-4318-96a6-da559486664b.
For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities.

Query insprired by Azure Sentinel detection https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/ADFSDomainTrustMods.yaml
## Query
```
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

## Contributor info
**Contributor:** Blake Strom
**GitHub alias:** @bstrom
**Organization:** Microsoft 365 Defender
**Contact info:** blstrom@microsoft.com