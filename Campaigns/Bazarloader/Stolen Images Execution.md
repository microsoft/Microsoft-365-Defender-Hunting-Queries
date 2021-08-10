# Stolen Images
The "Stolen Images" Bazarloader campaign uses fake copyright infingement contact form emails and malicious files pretending to contain "stolen images" to trick users into downloading the malware.

## Query
This query looks for instances of Wscript being used to execute the malicious "stolen images" file associated with this Bazarloader campaign. 
```
DeviceProcessEvents
| where FileName =~ "wscript.exe" and ProcessCommandLine has_all("stolen", "images")
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
