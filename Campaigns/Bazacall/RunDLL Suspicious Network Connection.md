# RunDLL Suspicious Network Connections
During the chain of events from Bazacall to Bazaloader, RunDLL makes several network connections, including to command and control (C2) infrastructure. The command line for these connections contains a specific process paramter, ",GlobalOut" that can surface potentially malicious activity related to Bazacall and Bazaloader.

## Query
This query looks for network connection events made by the RunDll32.exe process that have a command line that contains the ",GlobalOut" process parameter. 
```
DeviceNetworkEvents
| where InitiatingProcessFileName =~ 'rundll32.exe' and InitiatingProcessCommandLine has ",GlobalOut"
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
| Command and control | v |  |
| Exfiltration |  |  |
| Impact |  |  |
| Vulnerability |  |  |
| Exploit |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |
| Ransomware |  |  |

## Contributor info

**Contributor:** Microsoft 365 Defender team
