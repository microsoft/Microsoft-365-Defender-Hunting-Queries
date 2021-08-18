# Jupyter AKA SolarMarker
Jupyter, otherwise known as SolarMarker, is a malware family and cluster of components known for its info-stealing and backdoor capabilities that mainly proliferates through search engine optimization manipulation and malicious advertising in order to successfully encourage users to download malicious templates and documents. This malware has been popular since 2020 and currently is still active as of 2021. 

# Deimos malware component execution

The following query checks specifically for the AMSI Script Content, signaling that the Deimos malware is loading for execution. This is most often seen loaded by Jupyter, but may be in accompaniment of other malware or Jupyter variants as well. 

## Query
```
DeviceEvents   
| where InitiatingProcessFileName =~ "powershell.exe"
| where ActionType == "AmsiScriptContent"
| where AdditionalFields endswith '[mArS.deiMos]::inteRaCt()"}'
| project InitiatingProcessParentFileName, InitiatingProcessFileName, InitiatingProcessCommandLine, ActionType, AdditionalFields
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
| Collection | v |  |
| Command and control |  |  |
| Exfiltration | v |  |
| Impact | v |  |
| Vulnerability |  |  |
| Exploit |  |  |
| Misconfiguration |  |  |
| Malware, component | v |  |
| Ransomware |  |  |


## Contributor info

**Contributor:** Microsoft Threat Protection team
