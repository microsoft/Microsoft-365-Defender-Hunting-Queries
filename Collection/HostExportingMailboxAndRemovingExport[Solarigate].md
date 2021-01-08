#  Host Exporting Mailbox and Removing Export
This hunting query looks for hosts exporting a mailbox from an on-prem Exchange server, followed by
that same host removing the export within a short time window. This pattern has been observed by attackers 
when exfiltrating emails from a target environment. A Mailbox export is unlikely to be a common command run so look for
activity from unexpected hosts and accounts.

Reference: https://www.volexity.com/blog/2020/12/14/dark-halo-leverages-solarwinds-compromise-to-breach-organizations/

Query insprired by Azure Sentinel detection https://github.com/Azure/Azure-Sentinel/blob/master/Hunting%20Queries/SecurityEvent/HostExportingMailboxAndRemovingExport.yaml
## Query
```
// Adjust the timeframe to change the window events need to occur within to alert
let timeframe = 1h;
DeviceProcessEvents
  | where FileName  in~ ("powershell.exe", "cmd.exe")
  | where ProcessCommandLine  contains 'New-MailboxExportRequest'
  | project-rename NewMailBoxExpCmd = ProcessCommandLine  
  | summarize by DeviceName , timekey = bin(Timestamp, timeframe), NewMailBoxExpCmd, AccountName 
  | join kind=inner (DeviceProcessEvents
  | where FileName in~ ("powershell.exe", "cmd.exe")
  | where ProcessCommandLine contains 'Remove-MailboxExportRequest'
  | project-rename RemoveMailBoxExpCmd = ProcessCommandLine
  | summarize by DeviceName, timekey = bin(Timestamp, timeframe), RemoveMailBoxExpCmd, AccountName) on DeviceName, timekey, AccountName
  | extend commands = pack_array(NewMailBoxExpCmd, RemoveMailBoxExpCmd)  
  | summarize by timekey, DeviceName, tostring(commands), AccountName
  | project-reorder timekey, DeviceName, AccountName, ['commands']
  | extend HostCustomEntity = DeviceName, AccountCustomEntity = AccountName
```
## Category
This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.
| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access |  |  |
| Execution |  |  |
| Persistence |  |  | 
| Privilege escalation |  |  |
| Defense evasion | |  | 
| Credential Access |  |  | 
| Discovery |  |  | 
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