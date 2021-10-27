# Macaw ransomware - Imminent Ransomware 
Directly prior to deploying Macaw ransomware in an organization, the attacker will run several commands designed to disable security tools and system recovery tools. 

## Query
This query looks for instances where the attacker has run a collection of commands designed to tamper with security tools and system recovery tools.
```
DeviceProcessEvents 
// Pivot on specific commands 
| where ProcessCommandLine has_any("-ExclusionPath", "Set-MpPreference", "advfirewall", "-ExclusionExtension", 
"-EnableControlledFolderAccess", "windefend", "onstart", "bcdedit", "Startup") 
// Making list of found commands 
| summarize ProcessCommandLine = make_set(ProcessCommandLine) by DeviceId, bin(Timestamp, 6h) 
// Extending columns for later aggregration, based on TTP 
| extend StartUpExclusionPath = iff(ProcessCommandLine has_all("-ExclusionPath", "Startup"), 1, 0) 
| extend DefenderTamp = iff(ProcessCommandLine has "Set-MpPreference" 
and ProcessCommandLine has_any( 
"-SevereThreatDefaultAction 6" 
"-HighThreatDefaultAction 6", 
"-ModerateThreatDefaultAction 6", 
"-LowThreatDefaultAction 6" 
"-ScanScheduleDay 8"), 1, 0) 
| extend NetshFirewallTampering = iff(ProcessCommandLine has_all( "netsh", "advfirewall", "allprofiles state off"), 1, 0) 
| extend BatExclusion = iff(ProcessCommandLine has_all("-ExclusionExtension", ".bat"), 1, 0) 
| extend ExeExclusion = iff(ProcessCommandLine has_all("-ExclusionExtension", ".exe"), 1, 0) 
| extend DisableControlledFolderAccess = iff(ProcessCommandLine has_all("-EnableControlledFolderAccess", "Disabled"), 1, 0) 
| extend ScDeleteDefend = iff(ProcessCommandLine has_all("sc", "delete", "windefend"), 1, 0) 
| extend BootTampering = iff(ProcessCommandLine has_all("bcdedit", "default") and ProcessCommandLine has_any ("recoveryenabled No", "bootstatuspolicy ignoreallfailures"), 1, 0) 
| extend SchTasks = iff(ProcessCommandLine has_all("/sc", "onstart", "system", "/create", "/delay"), 1, 0) 
// Summarizing found commands 
| summarize by NetshFirewallTampering ,BatExclusion, ExeExclusion, DisableControlledFolderAccess, ScDeleteDefend, SchTasks, BootTampering, DefenderTamp, StartUpExclusionPath, DeviceId, Timestamp 
// Adding up each piece of evidence 
| extend EvidenceCount = NetshFirewallTampering + BatExclusion + ExeExclusion + DisableControlledFolderAccess + ScDeleteDefend + SchTasks + BootTampering + DefenderTamp + StartUpExclusionPath 
| where EvidenceCount > 4 
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
| Ransomware | v |  |

## Contributor info

**Contributor:** Microsoft 365 Defender team
