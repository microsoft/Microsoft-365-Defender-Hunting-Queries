# List files copied to USB mounted drives
This query lists files copied to USB external drives with USB drive information based on FileCreated events associated with most recent USBDriveMount events befor file creations. But be aware that Advanced Hunting is not monitoring all the file types.

## Query
```
let UsbDriveMount = DeviceEvents
| where ActionType=="UsbDriveMounted"
| extend ParsedFields=parse_json(AdditionalFields)
| project DeviceId, DeviceName, DriveLetter=ParsedFields.DriveLetter, MountTime=Timestamp,
ProductName=ParsedFields.ProductName,SerialNumber=ParsedFields.SerialNumber,Manufacturer=ParsedFields.Manufacturer
| order by DeviceId asc, MountTime desc;
let FileCreation = DeviceFileEvents
| where InitiatingProcessAccountName != "system"
| where ActionType == "FileCreated"
| where FolderPath !startswith "C:\\"
| where FolderPath !startswith "\\"
| project ReportId,DeviceId,InitiatingProcessAccountDomain,
InitiatingProcessAccountName,InitiatingProcessAccountUpn,
FileName, FolderPath, SHA256, Timestamp, SensitivityLabel, IsAzureInfoProtectionApplied
| order by DeviceId asc, Timestamp desc;
FileCreation | lookup kind=inner (UsbDriveMount) on DeviceId
| where FolderPath startswith DriveLetter
| where Timestamp >= MountTime
| partition by ReportId ( top 1 by MountTime )
| order by DeviceId asc, Timestamp desc
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
| Exfiltration | v |  | 
| Impact |  |  |
| Vulnerability |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |

## Contributor info
Contributor: Yoshihiro Ichinose  
GitHub alias: YoshihiroIchinose  
Organization: Microsoft Japan Co., Ltd.  
Contact info: yoshi@microsoft.com  
