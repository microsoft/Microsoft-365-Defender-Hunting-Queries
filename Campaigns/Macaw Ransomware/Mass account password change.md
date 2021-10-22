# Macaw ransomware - Mass account password change 
Prior to deploying Macaw ransomware in an organization, adversaries will change the password for hundreds or thousands of accounts in order to lock users out of the network and impeded recovery efforts.

## Query
This query looks for instances of attackers changes hundreds of account passwords within short succession.
```
DeviceProcessEvents 
| where ProcessCommandLine has_all('user', '/Domain', '/Active:Yes', '/PasswordChg:No') 
| summarize commands=count() by DeviceId, bin(Timestamp, 1d)  
| where commands > 200 
```


## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.
| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access |  |  |
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
| Ransomware | v |  |

## Contributor info

**Contributor:** Microsoft 365 Defender team
