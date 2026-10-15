# Windows Process-Creation Auditing Investigation

**Date:** October 15, 2026  
**Environment:** Windows 11  
**Event ID:** 4688 — A new process has been created  
**Investigation type:** Audit configuration validation and process triage

## 1. Objective

Validate process-creation auditing, collect recent Windows Security events, and
assess selected process records using executable paths, parent processes,
account context, and digital-signature information.

## 2. Initial Finding: Audit Configuration Gap

The initial command:

`auditpol /get /subcategory:"Process Creation"`

returned:

`Process Creation: No Auditing`

This indicated that process-creation auditing was not enabled through this
audit-policy subcategory at the time of the check.

## 3. Remediation and Verification

Process-creation auditing was enabled for successful events using:

`auditpol /set /subcategory:"Process Creation" /success:enable`

Subsequent Security log queries returned recent Event ID 4688 records,
including events generated during a controlled Notepad test.

This verified that new process-creation events were available after the change.
The investigation did not establish the exact reason for the earlier events
or the complete history of the previous audit configuration.

## 4. Observed Process Activity

The collected records included:

| Process | Parent process | Initial assessment |
|---|---|---|
| AcerHardwareService.exe | AcerCentralService.exe | Vendor-related path; signature checked |
| AcerAgentService.exe | AcerCentralService.exe | Vendor-related path; signature checked |
| EOSOverlayRenderer-Win64-Shipping.exe | Same executable path | Requires behavioral context |
| dllhost.exe | svchost.exe | Consistent with a common Windows process relationship |
| Notepad.exe | Windows PowerShell or same executable path | Consistent with the controlled test and possible multiple instances |
| svchost.exe | services.exe | Consistent with a common Windows service-launch relationship |

These are preliminary assessments, not definitive malware verdicts.

## 5. Digital-Signature Checks

`Get-AuthenticodeSignature` returned `Valid` for all three checked files:

- `AcerHardwareService.exe`
- `AcerAgentService.exe`
- `EOSOverlayRenderer-Win64-Shipping.exe`

The first two reported the Microsoft Windows Hardware Compatibility Publisher.
The Epic overlay reported Epic Games Inc.

Valid signatures support confidence in file authenticity and publisher identity.
They do not prove that a file or its behavior is harmless.

## 6. Limitations

- Only a small sample of recent process-creation events was reviewed.
- Command-line arguments and a complete process ancestry were not analyzed.
- No file hashes, reputation checks, or behavioral investigation were performed.
- Parent-process relationships and executable paths alone cannot establish
  whether activity is benign or malicious.
- The cause of the initial absence of recent events was not conclusively established.

## 7. Conclusion

A process-creation auditing gap was identified and the audit policy was changed
to record successful process-creation events. Subsequent Event ID 4688 records
were observed. Three selected executables had valid Authenticode signatures.

Based on the available evidence, no confirmed malicious activity was established.
Further investigation would be required if additional suspicious indicators emerge.

## 8. Skills Practiced

- Windows Security auditing and Event ID 4688
- PowerShell event collection and XML field extraction
- Parent-child process triage
- Authenticode signature verification
- Evidence-based assessment and documentation
