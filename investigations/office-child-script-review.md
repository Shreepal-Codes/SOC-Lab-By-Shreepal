# Office-to-Scripting-Tool Detection Review

**Date:** 2026-10-17
**Data source:** Windows Security log
**Event ID:** 4688 — Process creation
**Lookback window:** 24 hours
**Severity:** Review required if a match is found

## Objective

Identify process-creation events where Microsoft Word, Excel,
PowerPoint, or Outlook launches a selected scripting tool.

## Detection logic

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

## Test results

- Process-creation events retrieved: 1,399
- Matching parent-child combinations: 0
- Result: No matches found in the selected window

## Interpretation

The query retrieved process-creation events and completed without
finding a parent-child combination covered by this rule.

This result does not establish that the host is free of malicious
activity. The detection covers only the listed process names and
relationships within the available logs and time window.

## Limitations

- Command-line fields may be blank in the available events.
- The rule does not inspect script contents or prove whether a
  process is malicious.
- Other parent processes, tools, and execution techniques are outside
  this rule's scope.
- A no-match result is not proof that the detection catches every
  relevant attack technique.

## Follow-up

1. Review the event fields and confirm parent-process extraction.
2. Validate the rule against a known benign test event or a controlled
   simulation in an isolated lab.
3. Consider additional detections for suspicious scripting behavior.
4. Record future tests and changes to the detection logic.

## Conclusion

The detection executed successfully against 1,399 retrieved events
and returned no matches. No malicious activity was confirmed by
this test.
