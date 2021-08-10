# Zip-Doc - Word Launching MSHTA
The pw protected zip attachment -> Word doc delivery method of Bazarloader utilizes Word to create an .hta file and launch it via MSHTA to connect to a malicious domain and pull down the Bazarloader paylaod.

## Query
This query looks for instnaces of Microsoft Word creating an .hta file
```
DeviceProcessEvents
| where InitiatingProcessFileName =~ 'WINWORD.EXE' and FileName =~ 'cmd.exe' and ProcessCommandLine has_all('hta')
```


## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.
| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access |  |  |
| Execution | v |  |
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
