# Cypherpunk remote execution through PSEXESVC

This query was originally published in the threat analytics report, *Cypherpunk ransomware leaves wake of tampered AVs*.

Cypherpunk is a human-operated ransomware campaign named after the unusual *.cypherpunk* extension given to encrypted files. 

The query below surfaces commands that follow the distinctive pattern Cypherpunk operators would use to remotely execute code.

## Query

```kusto
// Searches for possible Cypherpunk ransomware activity
DeviceProcessEvents
| where InitiatingProcessParentFileName startswith "psexe"
| where ProcessCommandLine has "Dvr /go"
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
| Ransomware | v |  |


## Contributor info

**Contributor:** Microsoft Threat Protection team
