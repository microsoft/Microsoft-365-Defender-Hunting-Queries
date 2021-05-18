# Possible File Copy to USB Drive

This query searches for file copies which occur within a period of time (by default 15 min) to volumes associated with USB drives. To change the period of time from when
the USB device was inserted, adjust the Tolerance value.

Happy hunting!

## Query

```
let Tolerance = 1h;
DeviceEvents
| where ActionType == "UsbDriveMounted"
| extend AdditionalFields = parse_json(AdditionalFields)
| evaluate bag_unpack(AdditionalFields)
| project UsbSessionStart = Timestamp, DeviceId, ActionType, tostring(DriveLetter), tostring(Manufacturer), tostring(ProductName), tostring(ProductRevision), tostring(SerialNumber), tostring(Volume), DriveId = hash_sha256(strcat(Manufacturer,ProductName,ProductRevision,SerialNumber)), UsbSessionEnd = Timestamp + Tolerance
| where isnotempty( DriveLetter)
| join kind=inner (
    DeviceFileEvents
    | where FolderPath !startswith 'c:' and FolderPath !startswith @'\'
) on DeviceId
| where Timestamp between (UsbSessionStart .. UsbSessionEnd) and FolderPath startswith DriveLetter
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
| Collection | v |  | 
| Command and control |  |  | 
| Exfiltration | v |  | 
| Impact |  |  |
| Vulnerability |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |


## Contributor info

**Contributor:** Michael Melone

**GitHub alias:** mjmelone

**Organization:** Microsoft

**Contact info:** @PowershellPoet
