# Detect activity by the penetration tool, MailSniper

This query was originally published in the threat analytics report, *MailSniper Exchange attack tool*.

[MailSniper](https://github.com/dafthack/MailSniper) is a tool that targets Microsoft Exchange Server. The core function is to connect to Exchange Server and search through emails. In support of this, it can perform reconnaissance, collection, exfiltration, and credential theft. MailSniper is used both by red teams running penetration tests, and by malicious actors.

Microsoft Defender Security Center may record the following alerts during and after an attack:

* Global mail search on Exchange using MailSniper
* Exchange mailbox or mail folder search using MailSniper
* Enumeration of Active Directory usernames using MailSniper
* Enumeration of the Exchange GAL using MailSniper
* Access to Exchange inboxes using MailSniper
* Password spraying using MailSniper
* Enumeration of domains and user accounts using MailSniper

The following query detects activity commonly associated with attacks run with MailSniper.

## Query

```Kusto
let dateRange = ago(10d);
//
let whoamiProcess = DeviceProcessEvents
| where ProcessCreationTime >= dateRange
| where FileName =~ 'whoami.exe' and InitiatingProcessParentFileName =~ 'powershell.exe'
| project DeviceId, whoamiTime = ProcessCreationTime, whoamiProcessName = FileName, 
whoamiParentName = InitiatingProcessParentFileName, whoamiParentPID = InitiatingProcessParentId;
//
let netProcess = DeviceProcessEvents 
| where ProcessCreationTime >= dateRange
| where FileName =~ 'net.exe' and InitiatingProcessParentFileName =~ 'powershell.exe'
| project DeviceId, netTime = ProcessCreationTime, ProcessCreationTime = FileName, 
netParentName = InitiatingProcessParentFileName, netParentPID = InitiatingProcessParentId;
//
let mailServerEvents = DeviceNetworkEvents
| where Timestamp >= dateRange
| where InitiatingProcessFileName =~ 'powershell.exe'
| where RemoteUrl contains 'onmicrosoft.com'
or RemoteUrl contains 'outlook.com'
| project DeviceId, mailTime = Timestamp, mailProcessName = InitiatingProcessFileName, 
mailPID = InitiatingProcessId;
//
mailServerEvents
| join netProcess on DeviceId 
| where netParentPID == mailPID and netParentName == mailProcessName 
| join whoamiProcess on DeviceId 
| where whoamiParentPID == mailPID and whoamiParentName == mailProcessName 
| where netTime < mailTime + 4h and netTime > mailTime - 4h
| where whoamiTime < mailTime + 4h and whoamiTime > mailTime - 4h
| project DeviceId, EstimatedIncidentTime = mailTime, ProcessName = mailProcessName, 
ProcessID = mailPID
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access | v |  |
| Execution |  |  |
| Persistence |  |  |
| Privilege escalation |  |  |
| Defense evasion |  |  |
| Credential Access | v |  |
| Discovery |  |  |
| Lateral movement |  |  |
| Collection | v |  |
| Command and control |  |  |
| Exfiltration | v |  |
| Impact |  |  |
| Vulnerability |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |

## Contributor info

**Contributor:** Microsoft Threat Protection team
