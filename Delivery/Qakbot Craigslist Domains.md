# Qakbot Craigslist Domains
Qakbot operators have been abusing the Craigslist messaging system to send malicious emails. These emails contain non-clickable links to malicious domains impersonating Craigslist, which the user is instructed to manually type into the address bar to access.

## Query
This query looks for network connections to domains impersonating Craigslist which are associated with the delivery of Qakbot.
```
DeviceNetworkEvents
| where RemoteUrl matches regex @"abuse\.[a-zA-Z]\d{2}-craigslist\.org"
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.
| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access | v |  |
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

**Contributor:** Microsoft 365 Defender team
