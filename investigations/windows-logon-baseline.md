# Investigation 001: Windows Logon Baseline

## 1. Objective

Review Windows Security logs to understand successful logon activity and establish a basic baseline for future investigations.

## 2. Environment

- Operating system: Windows 11
- Log source: Windows Security event log
- Data collection method: PowerShell `Get-WinEvent`
- Investigation date: 2026-10-14

## 3. Events Reviewed

- Event ID 4624: Successful logon
- Event ID 4625: Failed logon
- Event ID 4798: A process queried a user's local group membership

## 4. Findings

Reviewed the 15 most recent Event ID 4624 records.

The reviewed records shared these characteristics:

- Target account: `SYSTEM`
- Logon type: `5` (service logon)
- Process: `C:\Windows\System32\services.exe`
- Source IP: `-`

The observed pattern is consistent with Windows service activity. The available fields do not independently establish whether every event is benign.

No Event ID 4625 records were found in the seven-day search window. This means no matching records were returned by that query; it does not prove that failed logons never occurred.

## 5. Investigation Steps

1. Verified that PowerShell could read the Security event log.
2. Checked the configured Logon audit policy.
3. Queried Event ID 4625 for the previous seven days.
4. Retrieved recent successful-logon events.
5. Extracted relevant event fields using PowerShell and XML parsing.

## 6. Conclusion

The reviewed events show a consistent service-logon pattern. No clear indicator of malicious activity was identified from the fields examined.

Further investigation would require additional context, including service details, associated processes, and other correlated events.

## 7. Skills Practiced

- Windows Event Viewer and Security logs
- Event ID interpretation
- PowerShell event filtering
- XML parsing
- Basic logon-type analysis
- Evidence-based reporting and cautious conclusions

## 8. Limitations

This was a small baseline review, not a full security assessment. Only a limited set of events and fields was examined. No claim is made that the host is free from compromise.