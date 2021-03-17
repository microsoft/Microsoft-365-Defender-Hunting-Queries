# Email-Suspicious-Patterns-Analysis
This query will help you to Identify Suspicious Patterns
  - Normal Email Received vs Spam, Phish, Malware [Categorized by Microsoft]
  - Normal Email Received Moving Average vs Spam, Phish, Malware [Categorized by Microsoft] Moving Average
## Query

```
let startTime = now(-30d);
let endTime = now();
union EmailEvents, EmailAttachmentInfo
| where Timestamp between ( startTime .. endTime )
| where isnotempty(RecipientEmailAddress)
| extend suspiciousEmailFlag = iff(ThreatTypes has_any ("Spam","Phish","Malware"),1,0)
| summarize emailReceivedCount = count() by suspiciousEmailFlag, RecipientEmailAddress, Timestamp
| summarize avgEmailReceived = avg(emailReceivedCount), avgSuspiciousEmail = avg(suspiciousEmailFlag*30) by bin(Timestamp, 3h)
| serialize
//| extend movAvgEmailReceived = (avgEmailReceived + prev(avgEmailReceived,1,0) + prev(avgEmailReceived,2,0))/3.0
//| extend movAvgSuspiciousEmail = (avgSuspiciousEmail + prev(avgSuspiciousEmail,1,0) + prev(avgSuspiciousEmail,2,0))/0.5
| project avgEmailReceived, avgSuspiciousEmail, Timestamp
//| project movAvgEmailReceived, movAvgSuspiciousEmail, Timestamp
| sort by Timestamp asc
| render timechart

```

## Category
This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.
| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access |  | v |
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
| Exploit |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |
| Ransomware |  |  |


## Contributor info
**Contributor:** AjatShatru
**GitHub alias:** A-dd-Y
**Contact info:** https://www.linkedin.com/in/ajatshatrux
