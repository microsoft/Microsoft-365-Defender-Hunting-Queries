# Confluence and WebLogic servers targeted by campaign

This query was originally published in the threat analytics report, *Confluence and WebLogic abuse*.

2019 has seen several seemingly related campaigns targeting Atlassian Confluence Server and Oracle WebLogic Server. Although these campaigns use different implants and delivery methods, they consistently use the same infrastructure, and exploit the same vulnerabilities.

The campaigns have specifically targeted:

* [CVE-2019-3396](https://nvd.nist.gov/vuln/detail/CVE-2019-3396) - [Software update](https://jira.atlassian.com/browse/CONFSERVER-57974)
* [CVE-2019-2725](https://nvd.nist.gov/vuln/detail/CVE-2019-2725) - [Software update](https://www.oracle.com/security-alerts/alert-cve-2019-2725.html)

The following query detects activity broadly associated with these campaigns.

## Query

```Kusto
DeviceProcessEvents
| where Timestamp >= ago(7d)
| where 
// "Grandparent" process is Oracle WebLogic or some process loading Confluence
InitiatingProcessParentFileName == "beasvc.exe" or 
InitiatingProcessFileName == "beasvc.exe" 
or InitiatingProcessCommandLine contains "//confluence"
// Calculate for Base64 in Commandline
| extend Caps = countof(ProcessCommandLine, "[A-Z]", "regex"), 
Total = countof(ProcessCommandLine, ".", "regex")
| extend Ratio = todouble(Caps) / todouble(Total) 
| where
(
    FileName in~ ("powershell.exe" , "powershell_ise.exe") // PowerShell is spawned
    // Omit known clean processes
    and ProcessCommandLine !startswith "POWERSHELL.EXE  -C \"GET-WMIOBJECT -COMPUTERNAME"
    and ProcessCommandLine !contains "ApplicationNo"
    and ProcessCommandLine !contains "CustomerGroup"
    and ProcessCommandLine !contains "Cosmos"
    and ProcessCommandLine !contains "Unrestricted"
    and
    (
        ProcessCommandLine contains "$" // PowerShell variable declaration
        or ProcessCommandLine contains "-e " // Alias for "-EncodedCommand" parameter
        or ProcessCommandLine contains "encodedcommand"
        or ProcessCommandLine contains "wget"
        //or ( Ratio > 0.4 and Ratio < 1.0) // Presence of Base64 strings
    )
)
or
(
    FileName =~ "cmd.exe" // cmd.exe is spawned
    and ProcessCommandLine contains "@echo" and 
    ProcessCommandLine contains ">" // Echoing commands into a file
)
or
(
    FileName =~ "certutil.exe" // CertUtil.exe abuse
    and ProcessCommandLine contains "-split" 
    // the "-split" parameter is required to write files to the disk
)
| project
       Timestamp,
       InitiatingProcessCreationTime ,
       DeviceId ,
       Grandparent_PID = InitiatingProcessParentId,
       Grandparent = InitiatingProcessParentFileName,
       Parent_Account = InitiatingProcessAccountName,
       Parent_PID = InitiatingProcessId,
       Parent = InitiatingProcessFileName ,
       Parent_Commandline = InitiatingProcessCommandLine,
       Child_PID = ProcessId,
       Child = FileName ,
       Child_Commandline = ProcessCommandLine
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

| Technique, tactic, or state | Covered? (v=yes) | Notes |
|-|-|-|
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
| Misconfiguration |  |  |
| Malware, component |  |  |

## Contributor info

**Contributor:** Microsoft Threat Protection team
