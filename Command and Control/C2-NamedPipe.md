# Detects malicious SMB Named Pipes (used by common C2 frameworks)

Detects the creation of a [named pipe](https://docs.microsoft.com/en-US/openspecs/windows_protocols/ms-wpo/4de75e21-36fd-440a-859b-75accc74487c) used by known APT malware.

## Query

```Kusto
// maximum lookback time
let minTimeRange = ago(7d);
// this is what should be constantly tweaked with default C2 framework names, search uses has_any (wildcard)
let badPipeNames = pack_array(
    '\\psexec',                                     // PSexec default pipe
    '\\paexec',                                     // PSexec default pipe
    '\\remcom',                                     // PSexec default pipe
    '\\csexec',                                     // PSexec default pipe
    '\\isapi_http',                                 // Uroburos Malware Named Pipe
    '\\isapi_dg',                                   // Uroburos Malware Named Pipe
    '\\isapi_dg2',                                  // Uroburos Malware Named Pipe
    '\\sdlrpc',                                     // Cobra Trojan Named Pipe http://goo.gl/8rOZUX
    '\\ahexec',                                     // Sofacy group malware
    '\\winsession',                                 // Wild Neutron APT malware https://goo.gl/pivRZJ
    '\\lsassw',                                     // Wild Neutron APT malware https://goo.gl/pivRZJ
    '\\46a676ab7f179e511e30dd2dc41bd388',           // Project Sauron https://goo.gl/eFoP4A
    '\\9f81f59bc58452127884ce513865ed20',           // Project Sauron https://goo.gl/eFoP4A
    '\\e710f28d59aa529d6792ca6ff0ca1b34',           // Project Sauron https://goo.gl/eFoP4A
    '\\rpchlp_3',                                   // Project Sauron https://goo.gl/eFoP4A - Technical Analysis Input
    '\\NamePipe_MoreWindows',                       // Cloud Hopper Annex B https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf, US-CERT Alert - RedLeaves https://www.us-cert.gov/ncas/alerts/TA17-117A
    '\\pcheap_reuse',                               // Pipe used by Equation Group malware 77486bb828dba77099785feda0ca1d4f33ad0d39b672190079c508b3feb21fb0
    '\\gruntsvc',                                   // Covenant default named pipe
    '\\583da945-62af-10e8-4902-a8f205c72b2e',       // SolarWinds SUNBURST malware report https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html
    '\\bizkaz',                                     // Snatch Ransomware https://thedfirreport.com/2020/06/21/snatch-ransomware/
    '\\atctl',                                      // https://www.virustotal.com/#/file/a4ddb2664a6c87a1d3c5da5a5a32a5df9a0b0c8f2e951811bd1ec1d44d42ccf1/detection
    '\\userpipe',                                   // ruag apt case
    '\\iehelper',                                   // ruag apt case
    '\\sdlrpc',                                     // project cobra https://www.gdatasoftware.com/blog/2015/01/23926-analysis-of-project-cobra
    '\\comnap',                                     // https://www.gdatasoftware.com/blog/2015/01/23926-analysis-of-project-cobra
    '\\lsadump',                                    // Cred Dump-Tools Named Pipes
    '\\cachedump',                                  // Cred Dump-Tools Named Pipes
    '\\wceservicepipe',                             // Cred Dump-Tools Named Pipes
    '\\jaccdpqnvbrrxlaf',                           // PoshC2 default named pipe
    '\\svcctl',                                     // CrackMapExec default named pipe
    '\\csexecsvc'                                   // CSEXEC default named pipe
    '\\status_',                                    // CS default named pipes https://github.com/Neo23x0/sigma/issues/253
    '\\MSSE-',                                      // CobaltStrike default named pipe
    '\\status_',                                    // CobaltStrike default named pipe
    '\\msagent_',                                   // (target) CobaltStrike default named pipe
    '\\postex_ssh_',                                // CobaltStrike default named pipe
    '\\postex_',                                    // CobaltStrike default named pipe
    '\\Posh'                                        // PoshC2 default named pipe
);
DeviceEvents
| where ActionType == "NamedPipeEvent" and Timestamp > minTimeRange
| extend ParsedFields=parse_json(AdditionalFields)
| where ParsedFields.FileOperation == "File created"
| where ParsedFields.PipeName has_any (badPipeNames)
| project Timestamp, ActionType, DeviceName, InitiatingProcessAccountDomain, InitiatingProcessAccountName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, ParsedFields.FileOperation, ParsedFields.PipeName
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
| Command and control | v |  |
| Exfiltration |  |  |
| Impact |  |  |
| Vulnerability |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |

## Contributor info

**Contributor:** [@xknow_infosec](https://twitter.com/xknow_infosec)

This detection is a summary of knowledge already known. Credits only to original authors. Defender for Endpoint lately just added a new ActionType for SMB named pipes (NamedPipeEvent), which would allow new equal usecases now based on the same telemetry (for example replicating all Sysmon EventID 17/18 detections).

Original Authors / Credits / Ressources:
* https://github.com/SigmaHQ/sigma/blob/master/rules/windows/pipe_created/sysmon_psexec_pipes_artifacts.yml
* https://drive.google.com/file/d/1lKya3_mLnR3UQuCoiYruO3qgu052_iS_/view
* https://github.com/SigmaHQ/sigma/blob/master/rules/windows/pipe_created/sysmon_mal_namedpipes.yml
* https://github.com/SigmaHQ/sigma/blob/master/rules/windows/pipe_created/sysmon_mal_cobaltstrike.yml
* https://twitter.com/d4rksystem/status/1357010969264873472
* https://labs.f-secure.com/blog/detecting-cobalt-strike-default-modules-via-named-pipe-analysis/
* https://github.com/Neo23x0/sigma/issues/253
* https://github.com/SigmaHQ/sigma/blob/master/rules/windows/pipe_created/sysmon_cred_dump_tools_named_pipes.yml
* https://github.com/SigmaHQ/sigma/blob/master/rules/windows/pipe_created/sysmon_apt_turla_namedpipes.yml
* https://twitter.com/rpargman/status/1359961601160351744
