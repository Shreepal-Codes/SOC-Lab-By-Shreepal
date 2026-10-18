# Office-to-Scripting-Tool Detection: Hardened Validation

## Objective
Validate the hardened PowerShell detection against real Windows Security Event 4688 records.

## Run details
- Event source: Windows Security log
- Event ID: 4688
- Time window: 24 hours preceding the run
- Events retrieved: 3,133
- Events processed: 3,133
- Evaluated events: 3,133
- Unevaluable or parse-error events: 0
- Office-to-scripting-tool matches: 0

## Outcome
All retrieved records were processed and evaluated by the script. No matching parent-child process relationships were found in this window.

## Improvements in the hardened script
- Attempts ParentProcessName first and CreatorProcessName as a fallback.
- Tracks unevaluable records separately from evaluated records.
- Handles individual event parsing errors without stopping the full run.
- Reports retrieval, processing, evaluation, and match counts separately.

## Interpretation
No matching relationships were observed in this run. This does not prove the absence of malicious activity or establish that every relevant process launch was audited.

## Remaining validation
- Exercise the alternate parent-field fallback with synthetic XML.
- Test missing fields and malformed XML.
- Compare the script's output against known event examples.
- Review potential false positives and false negatives.
- Confirm audit coverage and event retention settings.
