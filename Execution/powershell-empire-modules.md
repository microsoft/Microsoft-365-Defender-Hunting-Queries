# Detect PowerShell Empire modules

This query was originally published in the threat analytics report, *Hunting for PowerShell Empire*

[PowerShell Empire](https://www.powershellempire.com/) is a modular toolkit used both by penetration testers and malicious actors. It offers a wide range of attack techniques, and has been observed in numerous attacks.

The following query returns events associated with PowerShell Empire's extensive list of modules.

More queries related to PowerShell Empire are listed under the [See also](#see-also) section below.

## Query

```Kusto
​DeviceEvents
// Find PowerShell cmdlets
| where ActionType == "PowerShellCommand"
// Parse the additional fields for commands
| extend Command = parse_json(AdditionalFields)
// Find the following 12 sets of commands specifically used by Empire
| where Command has_any(
// 1. Code execution
"Invoke-DllInjection", "Invoke-MetasploitPayload", "Invoke-ReflectivePEInjection",
"Invoke-Shellcode", "Invoke-ShellcodeMSIL",
// 2. Collection
"Get-BrowserInformation", "Get-ClipboardContents", "Get-FoxDump",
"Get-Keystrokes", "Get-Screenshot", "Get-USBKeystrokes", "Invoke-Inveigh",
"Invoke-NetRipper", "Invoke-NinjaCopy", "Out-Minidump",
// 3. Credential gathering
"Get-VaultCredential", "Invoke-CredentialInjection", "Get-DomainSPNTicket",
"Invoke-Kerberoast", "Invoke-Mimikatz", "Invoke-PowerDump",
"DumpHashes", "Invoke-SessionGopher", "DownloadAndExtractFromRemoteRegistry",
"Invoke-TokenManipulation",
// 4. Data exfiltration
"Invoke-EgressCheck", "Invoke-ExfilDataToGitHub", "Invoke-PostExfil",
// 5. Exploitation
"Invoke-EternalBlue", "Exploit-JMXConsole", "Exploit-JBoss", 
"Exploit-Jenkins", 
// 6. Lateral movement
"Invoke-DCOM", "Invoke-ExecuteMSBuild", "Invoke-ExecuteMSBuildHelper",
"Invoke-InveighRelay", "Invoke-PsExec", "Invoke-PsExecCmd",
"Invoke-SMBExec", "Invoke-SQLOSCmd", "Invoke-SSHCommand"
// 7. Management
"Invoke-PSInject", "Invoke-RunAs", "Invoke-MailSearch",
"Invoke-SearchGAL", "Disable-SecuritySettings", "New-HoneyHash", 
"Set-MacAttribute"
// 8. Persistence
"Get-SecurityPackages", "Invoke-BackdoorLNK", "New-ElevatedPersistenceOption",
"New-UserPersistenceOption", "Add-Persistence", "Invoke-CallbackIEX",
"Add-PSFirewallRules", "Invoke-PortBind", "Invoke-PacketKnock", 
// 9. Privilege escalation
"Get-GPPPassword", "Get-SiteListPassword", "Get-SystemNamedPipe",
"Get-System", "Get-SystemToken", "Invoke-BypassUAC", 
"Inject-BypassStuff", "Invoke-BypassUACTokenManipulation", "Invoke-EnvBypass",
"Invoke-EventVwrBypass", "Invoke-FodHelperBypass", "Invoke-MS16032",
"Invoke-MS16135", "Invoke-SDCLTBypass", "Invoke-Tater",
"Invoke-WScriptBypassUAC", "Invoke-ServiceAbuse", "Find-ProcessDLLHijack",
"Get-ModifiableScheduledTaskFile",
// 10. Recon
"Get-SQLServerLoginDefaultPw", "Get-SQLSysadminCheck", "Find-Fruit",
// 11. Situational awareness
"Find-TrustedDocuments", "Get-ComputerDetails", "Get-SystemDNSServer", 
"Invoke-Paranoia", "Invoke-WinEnum", "Invoke-BloodHound", 
"Get-SPN", "Invoke-ARPScan", "Invoke-Portscan", 
"Invoke-ReverseDNSLookup", "Invoke-SMBAutoBrute", "Invoke-SMBScanner",
"powerview",
// 12. Trolling
"Get-RickAstley")
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

| Technique, tactic, or state | Covered? (v=yes) | Notes |
|-|-|-|
| Initial access | v |  |
| Execution | v |  |
| Persistence | v |  |
| Privilege escalation | v |  |
| Defense evasion | v |  |
| Credential Access | v |  |
| Discovery | v |  |
| Lateral movement | v |  |
| Collection | v |  |
| Command and control | v |  |
| Exfiltration | v |  |
| Impact | v |  |
| Vulnerability |  |  |
| Misconfiguration |  |  |
| Malware, component | v |  |

## See also

* [Return alerts for PowerShell Empire](../Protection%20events/powershell-empire-alerts.md)
* [Detect Base64-encoded PowerShell process and network creation commands](../Defense%20evasion/base64-encoded-powershell-commands.md)
* [Detect obfuscated PowerShell commands](../Defense%20evasion/obfuscated-powershell-commands.md)
* [Detect PowerShell commands to connect to remote hosts](../General%20queries/powershell-remote-connection.md)
* [Detect PowerShell commands executed from remote host](../Execution/powershell-execution-from-repo.md)

## Contributor info

**Contributor:** Microsoft Threat Protection team
