# Endpoint AV version report
This query will identify the Microsoft Defender Antivirus Engine version and Microsoft Defender Antivirus Security Intelligence version (and timestamp), Product update version (aka Platform Update version) as well as the Microsoft Defender Antivirus Mode on the endpoint (Active, Passive, etc.).

## Query
```
let avmodetable = DeviceTvmSecureConfigurationAssessment
| where ConfigurationId == "scid-2010" and isnotnull(Context)
| extend avdata=parsejson(Context)
| extend AVMode = iif(tostring(avdata[0][0]) == '0', 'Active' , iif(tostring(avdata[0][0]) == '1', 'Passive' ,iif(tostring(avdata[0][0]) == '4', 'EDR Blocked' ,'Unknown')))
| project DeviceId, AVMode;
DeviceTvmSecureConfigurationAssessment
| where ConfigurationId == "scid-2011" and isnotnull(Context)
| extend avdata=parsejson(Context)
| extend AVSigVersion = tostring(avdata[0][0])
| extend AVEngineVersion = tostring(avdata[0][1])
| extend AVSigLastUpdateTime = tostring(avdata[0][2])
| extend AVProductVersion = tostring(avdata[0][3]) 
| project DeviceId, DeviceName, OSPlatform, AVSigVersion, AVEngineVersion, AVSigLastUpdateTime, AVProductVersion, IsCompliant, IsApplicable
| join avmodetable on DeviceId
| project-away DeviceId1

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
| Vulnerability | v |  |
| Exploit |  |  |
| Misconfiguration | v |  |
| Malware, component |  |  |
| Ransomware |  |  |


## Contributor info
**Contributor:**  António Vasconcelos, Michael Melone, Tali Ash, Juli Hooper

**Contact info:**  julih@microsoft.com 
