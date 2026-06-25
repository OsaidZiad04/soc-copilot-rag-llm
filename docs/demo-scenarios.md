# Demo Scenarios

These scenarios are designed for classroom, recruiter, or technical-review demos. They use synthetic examples and should not include real incident data or private customer logs.

## 1. Brute Force Detection

Goal: show event correlation and suspicious authentication behavior.

Example input:

```text
2026-05-01T10:01:02Z host=dc01 event_id=4625 user=jsmith src_ip=203.0.113.10 status=failed_logon
2026-05-01T10:01:22Z host=dc01 event_id=4625 user=jsmith src_ip=203.0.113.10 status=failed_logon
2026-05-01T10:01:41Z host=dc01 event_id=4625 user=jsmith src_ip=203.0.113.10 status=failed_logon
2026-05-01T10:02:05Z host=dc01 event_id=4624 user=jsmith src_ip=203.0.113.10 status=successful_logon
```

Suggested workflow:

1. Open `Investigation`.
2. Paste each event as a separate event.
3. Run the analysis.

Expected discussion points:

- Repeated failed logons followed by success.
- Possible credential compromise.
- Source IP as a pivot.
- Account lockout, password reset, MFA review, and endpoint/network checks.

## 2. Suspicious PowerShell Execution

Goal: show alert triage for suspicious command execution.

Example input:

```text
Sysmon Event ID 1: powershell.exe launched by winword.exe with EncodedCommand and outbound connection to hxxp://example-c2.test/payload.ps1 from workstation FIN-WS-22.
```

Suggested workflow:

1. Open `Alert Analyzer`.
2. Paste the alert.
3. Run analysis.

Expected discussion points:

- Office process spawning PowerShell.
- Encoded command or download behavior.
- MITRE execution and defense-evasion techniques.
- Detection ideas such as parent-child process rules.

## 3. CVE Enrichment

Goal: summarize vulnerability risk and response priorities.

Example input:

```text
CVE-2024-0000 affects an internet-facing VPN appliance. Public exploit activity is suspected. The organization uses this appliance for remote access.
```

Suggested workflow:

1. Open the CVE analysis view or API route.
2. Submit the CVE ID and supporting text.
3. Review risk summary and remediation guidance.

Expected discussion points:

- Asset exposure.
- Exploitability.
- Patch and mitigation priority.
- Detection and hunting recommendations.

## 4. Sigma Rule Conversion

Goal: show detection engineering workflow across platforms.

Example Sigma:

```yaml
title: Suspicious PowerShell Network Download
id: 11111111-2222-3333-4444-555555555555
status: test
description: Detects PowerShell downloading content from the network.
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains:
      - 'Invoke-WebRequest'
      - 'DownloadString'
  condition: selection
level: high
```

Suggested workflow:

1. Open `Sigma Converter`.
2. Paste the rule or load the sample rule from `src/assets/sigma_samples/`.
3. Select target platforms.
4. Validate and convert.

Expected discussion points:

- Sigma parsing and validation.
- Platform-specific field mapping.
- Differences between SIEM, EDR, XDR, and IDS outputs.
- Need for analyst review before production deployment.

## 5. IoC Enrichment

Goal: demonstrate indicator type detection and enrichment.

Example input:

```text
8.8.8.8
malicious-example.test
http://malicious-example.test/payload
44d88612fea8a8f36de82e1278abb02f
```

Suggested workflow:

1. Open `IoC Enrichment`.
2. Submit the indicators.
3. Add optional provider API keys only in local runtime, not in repository files.

Expected discussion points:

- IP, domain, URL, and hash detection.
- Local indicator normalization.
- Optional external enrichment.
- False positives and source confidence.

## 6. Investigation Chain

Goal: show multi-event attack storytelling.

Example input:

```text
Event 1: Multiple failed logons for user backup_admin from 203.0.113.50.
Event 2: Successful logon for backup_admin from the same IP.
Event 3: powershell.exe executed an encoded command on FIN-WS-22.
Event 4: Host FIN-WS-22 connected to 198.51.100.77 over TCP 443.
Event 5: Security logs were cleared on FIN-WS-22.
```

Suggested workflow:

1. Open `Investigation`.
2. Paste each event.
3. Run correlation.

Expected discussion points:

- Initial access or valid-account abuse.
- Execution and command-and-control.
- Defense evasion through log clearing.
- Pivot points for deeper investigation.
- Containment and evidence-preservation actions.
