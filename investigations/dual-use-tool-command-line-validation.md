# Dual-Use Tool Detection — Command-Line Evidence and Triage Validation

## Objective

Validate the dual-use Windows process detection against synthetic test cases and real Windows Security process-creation events. Explicitly identify when command-line evidence is available or missing, and provide practical triage guidance to support analyst investigation.

## Detection scope

- **Windows Security Event ID:** 4688 — process creation
- **Lookback window:** 24 hours
- **Detection script:** `detections/dual-use-tool-process-review.ps1`
- **Production-logic tests:** `tests/test-dual-use-production-logic.ps1`
- **Regression tests:** `tests/test-dual-use-tool-process-review.ps1`

The detection reviews selected dual-use Windows utilities and gives additional priority to selected script-capable processes launched by Microsoft Office applications.

## Detection enhancements

The detection now includes a `TriageGuidance` field in each alert.

Guidance is assigned according to the observed process relationship:

| Process relationship | Investigation guidance |
|---|---|
| Office → scripting tool | Review Office document origin, user activity, and scripting-tool command line |
| Explorer → PowerShell | Determine whether the user intentionally launched PowerShell and review surrounding activity |
| svchost → rundll32 | Review the command line, referenced DLL path, and Windows service context |
| Other selected dual-use tool | Review the command line, parent process, and user activity |

These recommendations are investigation starting points, not automatic maliciousness verdicts. The priority and detection logic remain unchanged.

## Current test results

### Production-logic tests

| Metric | Result |
|---|---:|
| Total | 15 |
| Passed | 15 |
| Failed | 0 |

Coverage includes:

- Process detection and Office-parent prioritization
- Benign-process exclusions
- Missing process paths and malformed XML
- Creator-process fallback
- Command-line evidence availability
- Missing and whitespace-only command-line handling
- Office-specific triage guidance
- Explorer-to-PowerShell triage guidance
- svchost-to-rundll32 triage guidance
- General dual-use-tool triage guidance

The command-line evidence tests confirm:

- A recorded command line is marked `Available`.
- A missing command line is marked `Missing`.
- A whitespace-only command line is marked `Missing`.

### Regression tests

| Metric | Result |
|---|---:|
| Total | 6 |
| Passed | 6 |
| Failed | 0 |

All six existing regression scenarios passed, including PowerShell detection, Office-to-PowerShell prioritization, Certutil detection, and benign-process exclusions.

**Combined result: 21/21 tests passed.**

## Real Windows-log validation

Previously recorded validation run:

| Metric | Result |
|---|---:|
| Process-creation events processed | 4,419 |
| Alerts produced | 37 |
| Unevaluable events | 0 |
| Processing errors | 0 |

The reviewed alert output showed `CommandLineStatus = Missing` for the displayed alerts.

Observed process patterns included PowerShell launched by Explorer, VS Code, PowerShell itself, and another installed application, as well as `rundll32.exe` launched by `svchost.exe`.

These observations are review leads, not proof of malicious activity. Parent-child relationships and executable names must be assessed alongside user context, command-line evidence, timing, and other available telemetry.

**Note:** The real-log figures above are from an earlier validation run. They have not been presented as a new run of the triage-enhanced version.

## Evidence limitation

A missing command line means the event does not provide usable command-line evidence to this detection. It does **not** establish that the process is malicious, and it does not explain by itself why the field is absent.

When command-line evidence is missing, the analyst should record the limitation and seek corroborating telemetry where available.

Triage guidance also does not establish whether an event is malicious. It identifies useful investigative directions that require analyst verification.

## Conclusion

The detection now combines process-based review, priority assignment, explicit command-line evidence status, and context-specific triage guidance.

The latest validation passed all 15 production-logic tests and all six regression scenarios, for a combined result of 21/21 passing tests.

The earlier real-log validation processed 4,419 process-creation events and produced 37 alerts without unevaluable events or processing errors.

Further work should assess collection coverage, alert quality, and execution performance without weakening detection behavior.

## Reproduction

Run the production-logic tests:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\test-dual-use-production-logic.ps1
```

Run the regression tests:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\test-dual-use-tool-process-review.ps1
```



---

## Process Ancestry and Lifetime Validation

### Objective

Investigate whether Windows Security Event IDs 4688 and 4689 can be correlated to reconstruct process ancestry while accounting for PID reuse and process lifetime.

The objective was to move beyond immediate parent-process detection and establish a foundation for reliable multi-level process ancestry analysis.

### Audit Configuration

The following Windows auditing settings were verified:

- Process Creation: Success
- Process Termination: Success

The Security event log maximum size was increased from 20 MB to 100 MB.

Process Termination auditing was enabled during this investigation. Historical absence of termination events must not be interpreted as proof that processes remained alive.

### Event Field Mapping

| Event ID | Field | Meaning |
|---|---|---|
| 4688 | NewProcessId | PID assigned to the newly created process |
| 4688 | ProcessId | Creator/parent PID |
| 4688 | NewProcessName | Created process executable |
| 4689 | ProcessId | PID of the terminated process |
| 4689 | ProcessName | Terminated executable |
| 4689 | Status | Process termination status |

Event PID values are hexadecimal strings, whereas Windows CIM process information generally reports decimal PIDs. Conversion is required before comparing values from the two sources.

### Historical Process Ancestry Investigation

A controlled Notepad process was used to investigate multi-level process ancestry.

The following Event ID 4688 records were identified:

| Process | PID | Parent PID | Creation Time | Record ID |
|---|---|---|---|---|
| winlogon.exe | 0x7cac | 0x59f4 | Nov 23, 12:40:24 AM | 2402563 |
| userinit.exe | 0x2854 | 0x7cac | Nov 23, 5:50:31 PM | 2402676 |
| explorer.exe | 0x2e3c | 0x2854 | Nov 23, 5:50:31 PM | 2402682 |
| powershell.exe | 0x7ba8 | 0x2e3c | Nov 23, 8:34:19 PM | 2406832 |
| Notepad.exe | 0x7918 | 0x7ba8 | Nov 23, 9:24:52 PM | 2409153 |

This established a candidate ancestry chain:

winlogon.exe → userinit.exe → explorer.exe → powershell.exe → Notepad.exe

The parent-child PID relationships were supported by the corresponding creation events and process information.

### PID Reuse Discovery

Multiple historical Event ID 4688 records were found using PID 0x2e3c:

- November 17: explorer.exe
- November 18: backgroundTaskHost.exe
- November 23: explorer.exe

This demonstrates that Windows can reuse a PID for different process instances.

Consequently, matching a child's parent PID to any historical process with the same PID is insufficient to establish ancestry.

A reliable correlation must consider:

- Process creation timestamps
- Process termination timestamps
- PID reuse
- Available event-log coverage
- Potential audit gaps

### Controlled Process Lifetime Validation

A second Notepad process was launched using PowerShell.

Process details:

| Field | Value |
|---|---|
| Process | Notepad.exe |
| PID | 0x441c (17436) |
| Parent PID | 0x7ba8 (31656) |
| Creation Time | Nov 23, 9:46:08 PM |

**Event ID 4688 — Creation**

- Record ID: 2409527
- Time: 9:46:08 PM
- NewProcessId: 0x441c
- Parent ProcessId: 0x7ba8

The process was subsequently terminated.

**Event ID 4689 — Termination**

- Record ID: 2409552
- Time: 9:49:56 PM
- ProcessId: 0x441c
- Status: 0xffffffff

Both events referenced the same PID and executable.

The observed process lifetime was approximately 3 minutes and 48 seconds.

This successfully demonstrated correlation between process creation and termination events.

### Telemetry Limitations

During the historical investigation, no Event ID 4689 records were found between midnight and 6 PM on November 23.

However, multiple termination events were present later that evening.

Although Process Termination auditing was subsequently confirmed as enabled, the earlier absence of events means historical process lifetimes could not be established reliably.

The investigation therefore distinguishes between:

- Confirmed process creation relationships
- Confirmed process termination events
- Candidate ancestry relationships
- Unresolved process lifetime continuity

The absence of a termination event is not proof that a process remained alive.

### Findings and Next Steps

The investigation established that:

1. Event ID 4688 provides useful process creation and parent PID information.
2. Event ID 4689 provides process termination information.
3. Matching creation and termination events by PID can establish an observed process lifetime when the telemetry is available.
4. PID reuse can create false ancestry relationships if process lifetimes are ignored.
5. Historical ancestry reconstruction must account for missing events and incomplete telemetry.

The next development objective is a separate process ancestry analysis module.

The planned module will:

- Parse Event IDs 4688 and 4689.
- Normalize hexadecimal process identifiers.
- Correlate process creation and termination records.
- Account for PID reuse.
- Reconstruct multi-level process ancestry where evidence supports it.
- Identify unresolved or ambiguous relationships.
- Include synthetic tests for PID reuse, missing termination events, and incomplete ancestry.

The existing production dual-use detection logic will remain unchanged until the separate ancestry analysis module has been designed and validated.
