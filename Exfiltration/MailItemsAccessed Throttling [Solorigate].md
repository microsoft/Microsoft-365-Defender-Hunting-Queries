# MailItemsAccessed Throttling [Solorigate] 

The new MailItemsAccessed action is part of the new Advanced Audit functionality. It's part of Exchange mailbox auditing and is enabled by default for users that are assigned an Office 365 or Microsoft 365 E5 license or for organizations with a Microsoft 365 E5 Compliance add-on subscription.

If more than 1,000 MailItemsAccessed audit records are generated in less than 24 hours, Exchange Online will
stop generating auditing records for MailItemsAccessed activity. When a mailbox is throttled, MailItemsAccessed
activity will not be logged for 24 hours after the mailbox was throttled. If this occurs, there's a potential that
mailbox could have been compromised during this period. 
The recording of MailItemsAccessed activity will be resumed following a 24-hour period.

The query is looking for MailItemsAccessed Throttling when the operation is done by a ClientApplication

https://docs.microsoft.com/en-us/microsoft-365/compliance/mailitemsaccessed-forensics-investigations?view=o365-worldwide#the-mailitemsaccessed-mailbox-auditing-action
https://docs.microsoft.com/en-us/microsoft-365/compliance/mailitemsaccessed-forensics-investigations?view=o365-worldwide


## Query
```
let starttime = 2d;
let endtime = 1d;
CloudAppEvents
| where Timestamp between (startofday(ago(starttime))..startofday(ago(endtime)))
| where ActionType == "MailItemsAccessed"
| where isnotempty(RawEventData['ClientAppId']) and RawEventData['OperationProperties'][1] has "True" 
| project Timestamp, RawEventData['OrganizationId'],AccountObjectId,UserAgent
```
## Category
This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.
| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access |  |  |
| Execution |  |  |
| Persistence | |  | 
| Privilege escalation |  |  |
| Defense evasion |  |  | 
| Credential Access |  |  | 
| Discovery |  |  | 
| Lateral movement |  |  | 
| Collection |  |  | 
| Command and control |  |  | 
| Exfiltration | V |  | 
| Impact |  |  |
| Vulnerability |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |

## Contributor info
**Contributor:** Shilo Yair
**GitHub alias:** shilo.yair
**Organization:** Microsoft 365 Defender
**Contact info:** shyair@microsoft.com
