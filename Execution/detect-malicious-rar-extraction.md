# Detect CVE-2018-15982 exploit used to extract file from malicious RAR archive

This query was originally published in the threat analytics report, *CVE-2018-15982 exploit attacks*.

[CVE-2018-15982](https://nvd.nist.gov/vuln/detail/CVE-2018-15982) is an exploit of Adobe Flash Player, that allows for remote execution of arbitrary code. It has since been [patched](https://helpx.adobe.com/security/products/flash-player/apsb18-42.html).

Actors have been observed using this vulnerability in targeted attacks. Exploits for CVE-2018-15982 have also been included in several exploit kits.

In some initial attacks exploiting CVE-2018-15982, attackers sent targets spear-phishing emails. The emails would include an attached RAR archive, which contained a lure document, as well as a second archive disguised as a *.jpg* file. Opening the document would automatically run an embedded Flash ActiveX control. This, in turn, would call a script containing the exploit. The exploit's ability to run arbitrary code would be employed to unpack and run a payload from the second archive. The payload is a backdoor used both to achieve persistance and for command and control.

The following query detects possible instances of a payload being extracted by the exploit.

## Query

```Kusto
DeviceProcessEvents
| where FileName == "cmd.exe"
| where ProcessCommandLine contains @"set path=%ProgramFiles(x86)%\WinRAR;C:\Program Files\WinRAR;"
| where ProcessCommandLine contains @"cd /d %~dp0 & rar.exe e -o+ -r -inul*.rar"
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access | v |  |
| Execution | v |  |
| Persistence | v |  | 
| Privilege escalation |  |  |
| Defense evasion |  |  | 
| Credential Access |  |  | 
| Discovery |  |  | 
| Lateral movement |  |  | 
| Collection |  |  | 
| Command and control | v |  | 
| Exfiltration |  |  | 
| Impact |  |  |
| Vulnerability |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |


## Contributor info

**Contributor:** Contributor: Microsoft Threat Protection team
