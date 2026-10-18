# Office-to-Scripting-Tool Detection: End-to-End Log Validation

**Date:** 2026-10-18
**Data source:** Windows Security log
**Event ID:** 4688 — Process creation
**Lookback:** 24 hours

## Objective

Validate real-event retrieval, XML field extraction, parent-child
process parsing, and matching behavior for the Office-to-scripting-tool
detection rule.

## Results

| Validation check | Result |
|---|---:|
| Events retrieved | 2,670 |
| Events parsed | 2,670 |
| Events missing parent or child process names | 0 |
| Office-to-scripting-tool matches | 0 |

## Detection scope

Office parent processes:
- winword.exe
- excel.exe
- powerpnt.exe
- outlook.exe

Selected child processes:
- powershell.exe
- pwsh.exe
- wscript.exe
- cscript.exe
- mshta.exe

## Interpretation

The script successfully retrieved and parsed 2,670 real Windows
process-creation events. Both parent and child process names were
available in all parsed records. No process relationship matched the
specified detection rule in the selected time window.

This is a no-match result. It does not prove that the host is free of
malicious activity or that the detection covers every attack technique.

## Limitations

- No matching real event was available to confirm a real-world positive
  alert through the complete pipeline.
- Process names and parent-child relationships do not establish intent.
- Command-line fields may be blank.
- The detection covers only the listed process names and relationships.
- The current test does not measure false-negative rates.

## Next steps

1. Test a matching event against the rule in a controlled environment.
2. Confirm the event fields and alert output for a known test case.
3. Review other relevant process relationships as part of host baselining.
4. Update this report if further testing reveals defects or limitations.

## Conclusion

Real-log retrieval and parsing succeeded for all 2,670 returned events.
No matching Office-to-scripting-tool relationships were found.
A positive end-to-end detection test remains outstanding.
