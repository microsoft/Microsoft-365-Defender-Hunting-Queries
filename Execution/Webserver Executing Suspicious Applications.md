# Webserver Executing Suspicious Applications

This query looks for common webserver process names and identifies any processes launched using a scripting language (cmd, powershell, wscript, cscript), common initial profiling commands (net \ net1 \ whoami \ ping \ ipconfig),or admin commands (sc).  Note that seeing thisactivity doesn't immediately mean you have a breach, though you might consider  reviewing and honing the where clause to fit your specific web applications.

Those who don't mind false positives should consider also adding database process names to this list as well (i.e. sqlservr.exe) to identify potential abuse of xp_cmdshell.

## Query

```
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ('w3wp.exe', 'httpd.exe') // 'sqlservr.exe')
| where FileName in~ ('cmd.exe', 'powershell.exe', 'cscript.exe', 'wscript.exe', 'net.exe', 'net1.exe', 'ping.exe', 'whoami.exe')
| summarize instances = count() by ProcessCommandLine, FolderPath, DeviceName, DeviceId 
| order by instances asc
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
| Misconfiguration |  |  |
| Malware, component |  |  |


## Contributor info

**Contributor:** Michael Melone

**GitHub alias:** mjmelone

**Organization:** Microsoft

**Contact info:** @PowershellPoet
