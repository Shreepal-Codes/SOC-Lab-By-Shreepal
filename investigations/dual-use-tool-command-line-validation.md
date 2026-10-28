# Dual-Use Tool Detection — Command-Line Evidence Validation

## Objective

Validate the dual-use Windows process detection against synthetic test cases and real Windows Security process-creation events. Explicitly identify when command-line evidence is available or missing.

## Detection scope

- **Windows Security Event ID:** 4688 — process creation
- **Lookback window:** 24 hours
- **Detection script:** `detections/dual-use-tool-process-review.ps1`
- **Production-logic tests:** `tests/test-dual-use-production-logic.ps1`
- **Regression tests:** `tests/test-dual-use-tool-process-review.ps1`

The detection reviews selected dual-use Windows utilities and gives additional priority to selected script-capable processes launched by Microsoft Office applications.

## Test results

Production-logic tests:

- Total: 11
- Passed: 11
- Failed: 0

Coverage includes process detection, Office-parent priority, benign-process exclusions, missing process paths, malformed XML, parent-process fallback, and command-line evidence status.

The command-line evidence tests confirmed:

- A recorded command line is marked `Available`.
- A missing command line is marked `Missing`.
- A whitespace-only command line is marked `Missing`.

The separate regression suite also passed all six existing scenarios.

## Real Windows-log validation

Recorded run:

| Metric | Result |
|---|---:|
| Process-creation events processed | 4,419 |
| Alerts produced | 37 |
| Unevaluable events | 0 |
| Processing errors | 0 |

The reviewed alert output showed `CommandLineStatus = Missing` for the displayed alerts.

Observed process patterns included PowerShell launched by Explorer, VS Code, PowerShell itself, and another installed application, as well as `rundll32.exe` launched by `svchost.exe`.

These observations are review leads, not proof of malicious activity. Parent-child relationships and executable names must be assessed alongside user context, command-line evidence, timing, and other available telemetry.

## Evidence limitation

A missing command line means the event does not provide usable command-line evidence to this detection. It does **not** establish that the process is malicious, and it does not explain by itself why the field is absent.

When command-line evidence is missing, the analyst should record the limitation and seek corroborating telemetry where available.

## Conclusion

The updated detection passed all 11 production-logic tests and all six regression scenarios. The real-log run processed 4,419 process-creation events and produced 37 alerts without unevaluable events or processing errors.

The `CommandLineStatus` field makes evidence availability explicit, improving the clarity of subsequent analyst review. Further work should assess collection coverage and execution performance without weakening detection behavior.

## Reproduction

Run the production-logic tests:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\test-dual-use-production-logic.ps1
```

Run the regression tests:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\test-dual-use-tool-process-review.ps1
```