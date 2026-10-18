# Office-to-Scripting-Tool Detection: Synthetic Pipeline Test

## Objective
Validate XML field extraction, executable-name extraction, and Office-to-scripting-tool matching using synthetic Event 4688-like XML.

## Test method
A controlled PowerShell test generated simplified XML records in memory. It did not create Windows Security events or launch Office applications or scripting tools.

## Results

| Parent process | Child process | Expected | Result |
|---|---|---|---|
| winword.exe | powershell.exe | Match | Passed |
| excel.exe | calc.exe | No match | Passed |
| explorer.exe | powershell.exe | No match | Passed |
| outlook.exe | wscript.exe | Match | Passed |

**Outcome:** 4/4 synthetic test cases passed.

## What this validates
- Synthetic XML fields can be extracted.
- Executable names can be extracted from process paths.
- The detection condition identifies the configured Office-parent and scripting-child pairs.
- The rule rejects the two tested non-matching pairs.

## Limitations
- These are synthetic records, not genuine Windows Security events.
- The XML structure is simplified and does not test every possible Event 4688 schema.
- The test does not demonstrate detection of an actual malicious execution.
- The real-log validation found no matching process relationships in its selected 24-hour window.

## Next steps
- Test fallback handling for alternate parent-process field names.
- Test missing or malformed fields.
- Validate against genuine events when suitable examples are available.
- Review false-positive and false-negative risks before using the rule operationally.
