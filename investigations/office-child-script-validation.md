# Office-to-Scripting-Tool Detection: Logic Validation

**Date:** 2026-10-18  
**Detection:** `detections/office-child-script-review.ps1`  
**Test type:** Synthetic parent-child matching tests

## Objective

Validate whether the detection's process-name matching logic identifies
selected scripting tools launched by Microsoft Office applications.

## Test cases

| Test | Expected | Actual | Result |
|---|---|---|---|
| winword.exe -> powershell.exe | Match | Match | PASS |
| excel.exe -> calc.exe | No match | No match | PASS |
| explorer.exe -> powershell.exe | No match | No match | PASS |
| outlook.exe -> wscript.exe | Match | Match | PASS |

## Results

- Synthetic test cases: 4
- Passed: 4
- Failed: 0

## Interpretation

All four synthetic tests produced the expected results. The tests support
the correctness of the parent-child process-name matching logic for the
tested cases.

## Limitations

- These tests use synthetic data, not actual Windows Security events.
- They do not validate XML event parsing or field extraction.
- They do not prove the complete detection works end to end.
- Process-name relationships alone do not establish malicious intent.
- A no-match result in real logs does not prove a host is safe.

## Next steps

1. Validate event-field extraction using a known 4688 event.
2. Test the complete detection pipeline in a controlled environment.
3. Record any false positives or missed detections discovered.

## Conclusion

The detection's parent-child matching logic passed all four synthetic
test cases. End-to-end validation remains outstanding.
