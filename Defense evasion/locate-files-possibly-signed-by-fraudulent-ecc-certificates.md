# Locate files possibly signed by fraudulent ECC certificates

This query was originally published in the threat analytics report, *CVE-2020-0601 certificate validation vulnerability*.

The Windows CryptoAPI Spoofing Vulnerability, [CVE-2020-0601](https://portal.msrc.microsoft.com/security-guidance/advisory/CVE-2020-0601), can be exploited to spoof code-signing certificates. For example, an attacker could forge a certificate that fraudulently lists Microsoft as the issuer. This could allow an attacker to disguise a malicious executable as legitimate.

The vulnerability was patched with the [January 2020 Security Update](https://portal.msrc.microsoft.com/security-guidance/releasenotedetail/2020-Jan).

Use the following query to locate files containing ECC certificates that might have been crafted to appear as though they have been signed by Microsoft. It identifies files that list Microsoft as the root signer, yet don't correctly identify the signer name.

## Query

```
DeviceFileCertificateInfoBeta
| where Timestamp > ago(30d)
| where IsSigned == 1 and IsTrusted == 1 and IsRootSignerMicrosoft == 1
| where SignatureType == "Embedded"
| where Issuer !startswith "Microsoft" and Issuer !startswith "Windows"
| project Timestamp, DeviceName,SHA1,Issuer,IssuerHash,Signer,SignerHash,
CertificateCreationTime,CertificateExpirationTime,CrlDistributionPointUrls
```

## Category

This query can be used the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access |  |  |
| Execution |  |  |
| Persistence |  |  |
| Privilege escalation |  |  |
| Defense evasion | v |  |
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

**Contributor:** Microsoft Threat Protection Team
