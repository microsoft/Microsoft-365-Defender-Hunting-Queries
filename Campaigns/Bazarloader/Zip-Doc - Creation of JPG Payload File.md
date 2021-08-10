# Zip-Doc - Creation of JPG Payload File
In the campaign where Bazarloader is delivered via emails containing pw protected zip attachments, regsvr32.exe is used to launch a malicious payload that is disguised as a JPG file.

## Query
This query looks for instances of regsvr32.exe launching a file with a .jpg extension and summarizes the file name, SHA256, and Device ID for easy analysis. 
```
DeviceImageLoadEvents
| where InitiatingProcessFileName =~ "regsvr32.exe" and InitiatingProcessCommandLine has ".jpg" and FileName endswith ".jpg"
| summarize by FileName, SHA256, DeviceId, bin(Timestamp, 1d)
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
