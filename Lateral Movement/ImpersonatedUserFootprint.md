
# ImpersonatedUserFootprint

Azure ATP raises alert on suspicious Kerberos ticket, pointing to a potential overpass-the-hash attack. 
Once attackers gain credentials for a user with higher privileges, they will use the stolen credentials to sign into other devices and move laterally.
This query finds related sign-in events following overpass-the-hash attack to trace the footprint of the impersonated user.

## Query

```
AlertInfo
| where ServiceSource == "Azure ATP"
| where Title == "Suspected overpass-the-hash attack (Kerberos)"
| extend AlertTime = Timestamp 
| join 
    (
        AlertEvidence 
            | where EntityType == "User"
    ) 
    on AlertId 
| distinct AlertTime,AccountSid 
| join kind=leftouter  
    (
        DeviceLogonEvents
        | where LogonType == "Network" and ActionType == "LogonSuccess"
        | extend LogonTime = Timestamp 
    )
    on AccountSid 
| where LogonTime between (AlertTime .. (AlertTime + 2h))
| project DeviceId , AlertTime , AccountName , AccountSid 
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
| Lateral movement | V | https://attack.mitre.org/techniques/T1550/002/ | 
| Collection |  |  | 
| Command and control |  |  | 
| Exfiltration |  |  | 
| Impact |  |  |
| Vulnerability |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |


## Contributor info

Microsoft threat protection team
