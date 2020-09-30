
# When email was ZAPed.

This query allows to verify when email matching your search condition (by default based on presence of the URL) were ZAPed and compare it with original delivery time.

## Query

```
let URL=""; // Put your URL here
EmailUrlInfo
| where Url matches regex URL 
| join (EmailEvents | where DeliveryAction == "Delivered" and EmailDirection == "Inbound") on NetworkMessageId
| project Timestamp, NetworkMessageId, Url, SenderFromAddress, SenderIPv4, RecipientEmailAddress, Subject,DeliveryAction, DeliveryLocation
| join (EmailPostDeliveryEvents | where ActionType has "ZAP") on NetworkMessageId,RecipientEmailAddress 
| extend DeliveryTime=(Timestamp)
| extend ZAPTime=(Timestamp1)
| project DeliveryTime, ZAPTime, NetworkMessageId, SenderFromAddress, SenderIPv4,RecipientEmailAddress, Subject, DeliveryAction, DeliveryLocation
| sort by DeliveryTime  asc
```
## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access | x |  |
| Execution |  |  |
| Persistence |  |  | 
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

**Contributor:** Pawel Partyka

**GitHub alias:** pawp81

**Organization:** Microsoft

**Contact info:** @pawp81
