# Suspicious Registry Keys
ZLoader was delivered in a campaign in late summer 2021 using malvertising to download malicious .msi files onto affected machines. This campaign was originally tweeted by @MsftSecIntel on Twitter.
In this campaign, the malicious .msi files create registry keys that use that attacker-created comapny names.

## Query
This query looks for the suspicious registry keys created by the attacker-created companies.
```
DeviceRegistryEvents
| where RegistryValueData in('Flyintellect Inc.', 'Datalyst ou')
```


## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.
| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access |  |  |
| Execution |  |  |
| Persistence | v |  |
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

**Contributor:** Microsoft 365 Defender team
