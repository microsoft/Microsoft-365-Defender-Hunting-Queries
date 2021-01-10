#  Suspicious enumeration using Adfind tool
Attackers can use Adfind which is administrative tool to gather information about Domain controllers, ADFS Servers. They may also rename executables with other benign tools on the system.
Below query will look for adfind usage in commandline arguments irrespective of executable name in short span of time. You can limit query this to your DC and ADFS servers.
Below references talk about suspicious use of adfind by adversaries.
 - https://thedfirreport.com/2020/05/08/adfind-recon/
 - https://www.fireeye.com/blog/threat-research/2020/05/tactics-techniques-procedures-associated-with-maze-ransomware-incidents.html
 - https://www.microsoft.com/security/blog/2020/12/18/analyzing-solorigate-the-compromised-dll-file-that-started-a-sophisticated-cyberattack-and-how-microsoft-defender-helps-protect/

Query insprired by Azure Sentinel detection https://github.com/Azure/Azure-Sentinel/blob/master/Hunting%20Queries/SecurityEvent/Suspicious_enumeration_using_adfind.yaml
## Query
```
let startdate = 10d;
let lookupwindow = 2m;
let threshold = 3; //number of commandlines in the set below
let DCADFSServersList = dynamic (["DCServer01", "DCServer02", "ADFSServer01"]); // Enter a reference list of hostnames for your DC/ADFS servers
let tokens = dynamic(["objectcategory","domainlist","dcmodes","adinfo","trustdmp","computers_pwdnotreqd","Domain Admins", "objectcategory=person", "objectcategory=computer", "objectcategory=*"]);
DeviceProcessEvents
| where Timestamp between (ago(startdate) .. now())
//| where DeviceName in (DCADFSServersList) // Uncomment to limit it to your DC/ADFS servers list if specified above or any pattern in hostnames (startswith, matches regex, etc).
| where ProcessCommandLine  has_any (tokens)
| where ProcessCommandLine matches regex "(.*)>(.*)"
| summarize Commandlines = make_set(ProcessCommandLine), LastObserved=max(Timestamp) by bin(Timestamp, lookupwindow), AccountName, DeviceName, InitiatingProcessFileName, FileName
| extend Count = array_length(Commandlines)
| where Count > threshold
```
## Category
This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.
| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access |  |  |
| Execution | V |  |
| Persistence |  |  | 
| Privilege escalation |  |  |
| Defense evasion | |  | 
| Credential Access |  |  | 
| Discovery | V |  | 
| Lateral movement |  |  | 
| Collection | V |  | 
| Command and control |  |  | 
| Exfiltration |  |  | 
| Impact |  |  |
| Vulnerability |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |

## Contributor info
**Contributor:** Stefan Sellmer
**GitHub alias:** @stesell
**Organization:** Microsoft 365 Defender
**Contact info:** stesell@microsoft.com