# Suspicious Bitlocker Encryption

Looks for potential instances of bitlocker modifying registry settings to allow encryption, where it's executed via a .bat file.

## Query
```
DeviceProcessEvents
| where FileName =~ "reg.exe" 
// Search for BitLocker encryption being enabled without the chip
    and ProcessCommandLine has "EnableBDEWithNoTPM"
    // Using contains due to variant forms of capturing 1: 1, 0x1
    and (ProcessCommandLine has "true" or ProcessCommandLine contains "1")
// Search for this activity being launched by batch scripts, typically as: C:\Windows\[name].bat
| where InitiatingProcessCommandLine has_all (@"C:\Windows\", ".bat")

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
| Ransomware |V |  |


## Contributor info
**Contributor:** Microsoft 365 Defender
