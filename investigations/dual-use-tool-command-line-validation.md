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
