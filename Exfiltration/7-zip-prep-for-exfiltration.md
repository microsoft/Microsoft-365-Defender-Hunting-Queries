# 7-ZIP used by attackers to prepare data for exfiltration

This query was originally published in the threat analytics report, "Exchange Server zero-days exploited in the wild".

In early March 2021, Microsoft released [patches](https://msrc-blog.microsoft.com/2021/03/02/multiple-security-updates-released-for-exchange-server/) for four different zero-day vulnerabilities affecting Microsoft Exchange Server. The vulnerabilities were being used in a coordinated attack. For more information on the vulnerabilities, visit the following links:

* [CVE-2021-26855](https://nvd.nist.gov/vuln/detail/CVE-2021-26855)
* [CVE-2021-26857](https://nvd.nist.gov/vuln/detail/CVE-2021-26857)
* [CVE-2021-26858](https://nvd.nist.gov/vuln/detail/CVE-2021-26858)
* [CVE-2021-27065](https://nvd.nist.gov/vuln/detail/CVE-2021-27065)

The following query detects 7-zip activity associated with this threat. 7-ZIP is a legitimate tool used for file archiving; however, unusual 7-ZIP activity combined with other evidence might indicate that an attacker is compressing data for exfiltration.

More queries related to this threat can be found under the [See also](#See-also) section of this page.

## Query

```Kusto
DeviceProcessEvents | where FileName == "7z.exe" | where ProcessCommandLine contains "ProgramData\\pst"
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
| Exploit |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |
| Ransomware |  |  |

## See also

* [Reverse shell loaded using Nishang Invoke-PowerShellTcpOneLine technique](../Execution/reverse-shell-nishang.md)
* [Procdump dumping LSASS credentials](../Credential%20Access/procdump-lsass-credentials.md)
* [Exchange PowerShell snap-in being loaded](./exchange-powershell-snapin-loaded.md)
* [Powercat exploitation tool downloaded](../Delivery/powercat-download.md)
* [Exchange vulnerability creating web shells via UMWorkerProcess](../Execution/umworkerprocess-creating-webshell.md)
* [Exchange Server IIS dropping web shells and other artifacts](../Execution/exchange-iis-worker-dropping-webshell.md)
* [Exchange vulnerability launching subprocesses through UMWorkerProcess](../Execution/umworkerprocess-unusual-subprocess-activity.md)
* [Base64-encoded Nishang commands for loading reverse shell](../Execution/reverse-shell-nishang-base64.md)

## Contributor info

**Contributor:** Microsoft 365 Defender team
