# Powercat exploitation tool downloaded

This query was originally published in the threat analytics report, "Exchange Server zero-days exploited in the wild".

In early March 2021, Microsoft released [patches](https://msrc-blog.microsoft.com/2021/03/02/multiple-security-updates-released-for-exchange-server/) for four different zero-day vulnerabilities affecting Microsoft Exchange Server. The vulnerabilities were being used in a coordinated attack. For more information on the vulnerabilities, visit the following links:

* [CVE-2021-26855](https://nvd.nist.gov/vuln/detail/CVE-2021-26855)
* [CVE-2021-26857](https://nvd.nist.gov/vuln/detail/CVE-2021-26857)
* [CVE-2021-26858](https://nvd.nist.gov/vuln/detail/CVE-2021-26858)
* [CVE-2021-27065](https://nvd.nist.gov/vuln/detail/CVE-2021-27065)

The following query detects downloads of *powercat*, an exploitation tool for PowerShell. Although associated with these zero-day attacks, powercat is a multi-purpose tool that is also used by other groups of attackers.

More queries related to this threat can be found under the [See also](#See-also) section of this page.

## Query

```Kusto
DeviceProcessEvents | where FileName has_any ("cmd.exe", "powershell.exe", "PowerShell_ISE.exe") | where ProcessCommandLine endswith "powercat.ps1"
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access |  |  |
| Execution | v |  |
| Persistence |  |  | 
| Privilege escalation |  |  |
| Defense evasion |  |  | 
| Credential Access |  |  | 
| Discovery | v |  | 
| Lateral movement |  |  | 
| Collection |  |  | 
| Command and control |  |  | 
| Exfiltration | v |  | 
| Impact |  |  |
| Vulnerability |  |  |
| Exploit |  |  |
| Misconfiguration |  |  |
| Malware, component | v |  |
| Ransomware |  |  |

## See also

* [Reverse shell loaded using Nishang Invoke-PowerShellTcpOneLine technique](../Execution/reverse-shell-nishang.md)
* [Procdump dumping LSASS credentials](../Credential%20Access/procdump-lsass-credentials.md)
* [7-ZIP used by attackers to prepare data for exfiltration](../Exfiltration/7-zip-prep-for-exfiltration.md)
* [Exchange PowerShell snap-in being loaded](../Exfiltration/exchange-powershell-snapin-loaded.md)
* [Exchange vulnerability creating web shells via UMWorkerProcess](../Execution/umworkerprocess-creating-webshell.md)
* [Exchange Server IIS dropping web shells and other artifacts](../Execution/exchange-iis-worker-dropping-webshell.md)
* [Exchange vulnerability launching subprocesses through UMWorkerProcess](../Execution/umworkerprocess-unusual-subprocess-activity.md)
* [Base64-encoded Nishang commands for loading reverse shell](../Execution/reverse-shell-nishang-base64.md)

## Contributor info

**Contributor:** Microsoft 365 Defender team
