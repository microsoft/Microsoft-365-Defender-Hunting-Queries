# Possible File Copy to USB Drive

This query searches for file copies which occur within a period of time (by default 15 min) to volumes other than the C drive or UNC shares. By default, this query will
search all devices. A single device can be specified by entering the DeviceName in the DeviceNameToSearch variable. Additionally, to change the period of time from when
the USB device was inserted, adjust the TimespanInSeconds value.

Happy hunting!

## Query

```
let DeviceNameToSearch = ''; // DeviceName to search for. Leave blank to search all devices.
let TimespanInSeconds = 900; // Period of time between device insertion and file copy
let Connections =
DeviceEvents
| where (isempty(DeviceNameToSearch) or DeviceName =~ DeviceNameToSearch) and ActionType == "PnpDeviceConnected"
| extend parsed = parse_json(AdditionalFields)
| project DeviceId,ConnectionTime = Timestamp, DriveClass = tostring(parsed.ClassName), UsbDeviceId = tostring(parsed.DeviceId), ClassId = tostring(parsed.DeviceId), DeviceDescription = tostring(parsed.DeviceDescription), VendorIds = tostring(parsed.VendorIds)
| where DriveClass == 'USB' and DeviceDescription == 'USB Mass Storage Device';
DeviceFileEvents
| where (isempty(DeviceNameToSearch) or DeviceName =~ DeviceNameToSearch) and FolderPath !startswith "c" and FolderPath !startswith @"\"
| join kind=inner Connections on DeviceId
| where datetime_diff('second',Timestamp,ConnectionTime) <= TimespanInSeconds
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
