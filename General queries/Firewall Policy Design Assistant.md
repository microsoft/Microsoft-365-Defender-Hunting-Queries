# Firewall Policy Design Assistant
This query helps you design client firewall rules based on data stored within DeviceNetworkEvents. Folder paths are alias'ed to help represent the
files making or receiving network connections without dealing with duplication from path variance due to different root drive letter or user profile
association.

To make the report easy to read, inbound remote IP addresses are not calculated by default (this can be changed by setting the value of IncludeInboundRemoteIPs to true).
Also, the ephemeral range is defaulted to 49152 to help eliminate false detections.

## Query
```
let EphemeralRangeStart = 49152;
let IncludeInboundRemoteIPs = false;
let AliasPath = (SourcePath:(FolderPath:string, FileName:string))
{
SourcePath
    | extend AliasPath = tolower(
            case(
                //Modern style profile
                FolderPath startswith 'c:\\users\\', strcat('%UserProfile%', substring(FolderPath, indexof(FolderPath,'\\',11), strlen(FolderPath) - 11)),
                //Legacy style profile
                FolderPath startswith 'c:\\documents and settings\\', strcat('%UserProfile%', substring(FolderPath, indexof(FolderPath,'\\',27), strlen(FolderPath) - 27)),
                //Windir
                FolderPath contains @':\Windows\', strcat('%windir%', substring(FolderPath, 10)),
                //ProgramData
                FolderPath contains @':\programdata\', strcat('%programdata%', substring(FolderPath, 14)),
                // ProgramFiles
                FolderPath contains @':\Program Files\', strcat('%ProgramFiles%', substring(FolderPath, 16)),
                // Program Files (x86)
                FolderPath contains @':\Program Files (x86)\', strcat('%ProgramFilesx86%', substring(FolderPath, 22)),
                //Other
               FolderPath)
        )
};
let ServerConnections =
    DeviceNetworkEvents
    | where ActionType in ('InboundConnectionAccepted','ListeningConnectionCreated')
        and RemoteIPType != 'Loopback' 
        and LocalIP != RemoteIP 
        and RemoteIP !startswith '169.254' 
        and LocalPort < EphemeralRangeStart
    | distinct DeviceId, InitiatingProcessFolderPath, LocalPort;
union (
    DeviceNetworkEvents
    | where ActionType in ('InboundConnectionAccepted','ListeningConnectionCreated','ConnectionSuccess','ConnecitonFound','ConnectionRequest')
        and RemoteIPType != 'Loopback' 
        and LocalIP != RemoteIP 
        and RemoteIP !startswith '169.254' 
        and LocalPort < EphemeralRangeStart
    | join kind=leftsemi ServerConnections on DeviceId, InitiatingProcessFolderPath, LocalPort
    | project-rename FolderPath = InitiatingProcessFolderPath, FileName = InitiatingProcessFileName
    | invoke AliasPath()
    | extend Directionality = 'Inbound', Port = LocalPort, RemoteIP = iff(IncludeInboundRemoteIPs == true, RemoteIP,'')
),(
    DeviceNetworkEvents
    | where ActionType in ('ConnectionSuccess','ConnecitonFound','ConnectionRequest') 
        and RemoteIPType != 'Loopback' 
        and LocalIP != RemoteIP 
        and RemoteIP !startswith '169.254' 
        and LocalPort >= EphemeralRangeStart
    | join kind=leftanti ServerConnections on DeviceId, InitiatingProcessFolderPath, LocalPort
    | project-rename FolderPath = InitiatingProcessFolderPath, FileName = InitiatingProcessFileName
    | invoke AliasPath()
    | extend Directionality = 'Outbound', Port = RemotePort
)
| summarize ConnectionCount = count(), DistinctMachines = dcount(DeviceId), Ports = makeset(Port), RemoteIPs = makeset(RemoteIP) by Directionality, AliasPath
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
| Misconfiguration | v |  |
| Malware, component |  |  |

## Contributor info

**Contributor:** Michael Melone

**GitHub alias:** mjmelone

**Organization:** Microsoft

**Contact info:** @PowershellPoet \ https://melone.co
