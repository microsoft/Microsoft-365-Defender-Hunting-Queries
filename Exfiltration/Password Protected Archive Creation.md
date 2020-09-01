# Password Protected Archive Creation

One common technique leveraged by attackers is using archiving applications to package up files for exfiltration. In many cases, these archives are usually protected with a password to make analysis more difficult.  This query identifies applications which leverage a command line pattern which matches the 7zip and WinRAR command line executables to create or update an archive when a password is specified.  By detecting based on the command line we can avert attempts to dodge detection by renaming the application.

Happy hunting!

## Query

```
DeviceProcessEvents
| where ProcessCommandLine matches regex @"\s[aukfAUKF]\s.*\s-p"  // Basic filter to look for launch string
| extend SplitLaunchString = split(ProcessCommandLine, ' ') // Split on the space
| where array_length(SplitLaunchString) >= 5 and SplitLaunchString[1] in~ ('a','u','k','f') // look for calls to archive or update an archive specifically as the first argument
| mv-expand SplitLaunchString // cross apply the array
| where SplitLaunchString startswith "-p"  // -p is the password switch and is immediately followed by a password without a space
| extend ArchivePassword = substring(SplitLaunchString, 2, strlen(SplitLaunchString))
| project-reorder ProcessCommandLine, ArchivePassword // Promote these fields to the left
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
