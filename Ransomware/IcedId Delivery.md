# IcedId Delivery

Use this query to locate successful delivery of associated malicious downloads that can lead to ransomware

## Query
```
DeviceFileEvents 
| where InitiatingProcessFileName in~("msedge.exe", "chrome.exe", "explorer.exe", "7zFM.exe", "firefox.exe", "browser_broker.exe") 
| where FileOriginReferrerUrl has ".php" and FileOriginReferrerUrl has ".top" and FileOriginUrl  has_any("googleusercontent", "google", "docs")
```
## Category
This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.
| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access | V |  |
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
