# Detect activity associated with malicious DLL, cyzfc.dat

These queries was originally published in the threat analytics report, *Attacks on gov't, think tanks, NGOs*.

As described further in *[Analysis of cyberattack on U.S. think tanks, non-profits, public sector by unidentified attackers](https://www.microsoft.com/security/blog/2018/12/03/analysis-of-cyberattack-on-u-s-think-tanks-non-profits-public-sector-by-unidentified-attackers/)*, there was a very large spear-phishing campaign launched in November 2019.

The attackers would gain access to a target by having the user click on a link to a compromised website and download a .zip archive.

Once established on a target's device, the attackers used a malicious DLL named *cyzfc.dat* to execute additional payloads. They would call a function in the malicious DLL via the legitimate Windows process, [rundll32.exe](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/rundll32), to connect directly to their command-and-control (C2) servers.

The following queries detect activity associated with the malicious DLL, *cyzfc.dat.*, used in this campaign.

## Query

```Kusto
​// Query 1: Events involving the DLL container
let fileHash = "9858d5cb2a6614be3c48e33911bf9f7978b441bf";
find in (DeviceFileEvents, DeviceProcessEvents, DeviceEvents,
DeviceRegistryEvents, DeviceNetworkEvents, DeviceImageLoadEvents)
where SHA1 == fileHash or InitiatingProcessSHA1 == fileHash
| where Timestamp > ago(10d)

// Query 2: C2 connection
DeviceNetworkEvents
| where Timestamp > ago(10d)
| where RemoteUrl == "pandorasong.com"

// Query 3: Malicious PowerShell
DeviceProcessEvents
| where Timestamp > ago(10d)
| where ProcessCommandLine contains
"-noni -ep bypass $zk='JHB0Z3Q9MHgwMDA1ZTJiZTskdmNxPTB4MDAwNjIzYjY7JHRiPSJ"

// Query 4: Malicious domain in default browser commandline
DeviceProcessEvents
| where Timestamp > ago(10d)
| where ProcessCommandLine contains
"https://www.jmj.com/personal/nauerthn_state_gov"

// Query 5: Events involving the ZIP
let fileHash = "cd92f19d3ad4ec50f6d19652af010fe07dca55e1";
find in (DeviceFileEvents, DeviceProcessEvents, DeviceEvents,
DeviceRegistryEvents, DeviceNetworkEvents, DeviceImageLoadEvents)
where SHA1 == fileHash or InitiatingProcessSHA1 == fileHash
| where Timestamp > ago(10d)
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

| Technique, tactic, or state | Covered? (v=yes) | Notes |
|-|-|-|
| Initial access |  |  |
| Execution | v |  |
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
| Misconfiguration |  |  |
| Malware, component |  |  |

## Contributor info

**Contributor:** Microsoft Threat Protection team
