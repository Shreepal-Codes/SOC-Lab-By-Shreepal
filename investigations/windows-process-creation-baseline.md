# Investigation 002: Windows Process-Creation Baseline

## 1. Objective

Examine Windows Security Event ID 4688 to identify newly created processes and understand their parent-process relationships.

## 2. Data Source

- Operating system: Windows 11
- Log source: Windows Security
- Event ID: 4688 — A new process has been created
- Collection method: PowerShell `Get-WinEvent`
- Investigation date: 2026-10-14

## 3. Evidence Reviewed

Five recent process-creation events were examined.

| New Process | Parent Process |
|---|---|
| `lsass.exe` | `wininit.exe` |
| `LsaIso.exe` | `wininit.exe` |
| `services.exe` | `wininit.exe` |
| `winlogon.exe` | `smss.exe` |
| `csrss.exe` | `smss.exe` |

The observed executable paths were under `C:\Windows\System32`.

## 4. Analysis

The executable names, paths, and parent-process relationships are consistent with expected Windows startup activity.

The reviewed events did not contain usable values for the extracted username and command-line fields.

Executable paths and process names alone are insufficient to establish that a process is legitimate. Additional validation may include digital signatures, file hashes, process details, and correlated security events.

## 5. Conclusion

No obvious indicator of malicious process creation was identified in the five records reviewed. This is a limited baseline assessment, not a full host security assessment.

## 6. Skills Practiced

- Windows Event ID 4688 analysis
- PowerShell event collection
- XML event-data parsing
- Parent-child process analysis
- Evidence-based security reporting

## 7. Limitations

Only five events and a limited set of fields were reviewed. Command-line information was not available in the extracted output. No conclusions are made about unexamined events or the overall security of the host.