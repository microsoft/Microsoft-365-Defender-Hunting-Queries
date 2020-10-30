# Threat actor Phosphorus masquerading as conference organizers

Identify prior activity from this campaign using IOCs shared by Microsoft’s Threat Intelligence Center, or MSTIC.

Read more: https://blogs.microsoft.com/on-the-issues/2020/10/28/cyberattacks-phosphorus-t20-munich-security-conference/

## Query
```
//All emails from the threat actor Phosphorus, masquerading as conference organizers, based on the IOCs shared 
// by Microsoft’s Threat Intelligence Center in: https://blogs.microsoft.com/on-the-issues/2020/10/28/cyberattacks-phosphorus-t20-munich-security-conference/
let MaliciousSenders = dynamic(["t20saudiarabia@outlook.sa", "t20saudiarabia@hotmail.com", "t20saudiarabia@gmail.com", "munichconference@outlook.com",  
"munichconference@outlook.de", "munichconference1962@gmail.com"]);
EmailEvents
| where SenderFromAddress  in~ (MaliciousSenders)

//Filter for emails that were delivered check the FinalEmailAction to see if there was policy applied on this email
let MaliciousSenders = dynamic(["t20saudiarabia@outlook.sa", "t20saudiarabia@hotmail.com", "t20saudiarabia@gmail.com", "munichconference@outlook.com",  
"munichconference@outlook.de", "munichconference1962@gmail.com"]);
EmailEvents
| where SenderFromAddress  in~ (MaliciousSenders) and DeliveryAction == "Delivered"

//Filter for emails that were delivered and check if there was any action taken on them post delivery, by joining with EmailPostDeliveryEvents
let MaliciousSenders = dynamic(["t20saudiarabia@outlook.sa", "t20saudiarabia@hotmail.com", "t20saudiarabia@gmail.com", "munichconference@outlook.com",  
"munichconference@outlook.de", "munichconference1962@gmail.com"]);
EmailEvents
| where SenderFromAddress  in~ (MaliciousSenders) and DeliveryAction == "Delivered"
| join EmailPostDeliveryEvents on NetworkMessageId, RecipientEmailAddress 
```
## Category
This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.
| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access | V |  |
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
**Contributor:** Tali Ash

**GitHub alias:** tali-ash

**Organization:** Microsoft

**Contact info:** @Taliash1
