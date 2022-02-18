# Modification of exefile shell open key

Detect modification of the exefile shell open command, which is used to persist on a system without having to add other persistence mechanism. MITRE ATT&CK is T1546.001 (Event Triggered Execution: Change Default File Association).

The detection logic is also included in the [Sigma rule for asep modification.](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry_event/sysmon_asep_reg_keys_modification.yml) or in [Shell Open Registry Keys Manipulation](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry_event/win_registry_shell_open_keys_manipulation.yml) too.

## Query

```
// # exefile file handler open command manipulation
//
// MITRE ATT&CK: T1546.001 - Event Triggered Execution: Change Default File Association
//
// Registry edits by campaigns using lokibot malware (November 2021)
//
DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where RegistryKey has @"Classes\exefile\shell\open\command"
| project DeviceName, InitiatingProcessAccountName, RegistryKey, RegistryValueName, RegistryValueData, DeviceId, Timestamp
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access |  |  |
| Execution |  |  |
| Persistence | v | T1546.001, [Lokibot sample from Nov 2021](https://tria.ge/211119-gs7rtshcfr/behavioral2) | 
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
| Exploit |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |
| Ransomware |  |  |


## Contributor info
**Contributor:** Andreas Hunkeler
**GitHub alias:** @Karneades
**Organization:** Swisscom (Schweiz) AG

**Contact info:** https://twitter.com/swisscom_csirt
