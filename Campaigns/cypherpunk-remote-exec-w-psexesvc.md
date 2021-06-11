# Cypherpunk remote execution through PSEXESVC

This query was originally published in the threat analytics report, *Cypherpunk ransomware leaves wake of tampered AVs*.

Cypherpunk is a human-operated ransomware campaign named after the unusual *.cypherpunk* extension given to encrypted files. The attackers often used PSEXESVC, a service that helps the PsExe.exe utility run commands on a remote device. Both PSEXESVC and PsExe.exe are legitimate parts of Windows; however, they can be repurposed by attackers to perform malicious actions.

The query below can find instances of PSEXESVC being used to launch batch files, as often occurred in Cypherpunk attacks.

## Query

```kusto
// Searches for remote batch file launch using PSEXESVC.exe
DeviceProcessEvents
| where InitiatingProcessParentFileName startswith "psexe"
| where InitiatingProcessCommandLine has ".bat"
| where ProcessCommandLine has "DisableIOAVProtection"
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
