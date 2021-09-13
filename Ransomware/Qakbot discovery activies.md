# Qakbot discovery activities

Use this query to locate injected processes launching discovery activity. Qakbot has been observed leading to ransomware in numerous instances.

## Query
```
DeviceProcessEvents 
| where InitiatingProcessFileName in~('mobsync.exe','explorer.exe')
| where (FileName =~ 'net.exe' and ProcessCommandLine has_all('view','/all'))
     or (FileName =~ 'whoami.exe' and ProcessCommandLine has '/all')
     or (FileName =~ 'nslookup.exe' and ProcessCommandLine has_all('querytype=ALL','timeout=10'))
     or (FileName =~ 'netstat.exe' and ProcessCommandLine has '-nao')
     or (FileName =~ 'arp.exe' and ProcessCommandLine has '-a')
     or (FileName =~ 'ping.exe' and ProcessCommandLine has '-t' and ProcessCommandLine endswith '127.0.0.1')
| summarize DiscoveryCommands = dcount(ProcessCommandLine), make_set(InitiatingProcessFileName), make_set(FileName), make_set(ProcessCommandLine) by DeviceId, bin(Timestamp, 5m)   
| where DiscoveryCommands >= 3
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
