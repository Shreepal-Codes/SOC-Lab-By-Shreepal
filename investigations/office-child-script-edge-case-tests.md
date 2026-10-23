# Office-to-Script Detection: Edge-Case Test Results

## Objective

Validate the expected behavior of the Office child-process detection logic
against synthetic event data, including missing fields and malformed XML.

## Results

- Synthetic tests passed: 6
- Synthetic tests failed: 0
- Overall result: PASS

## Scenarios Covered

1. ParentProcessName takes precedence when available.
2. CreatorProcessName is used as a fallback when ParentProcessName is blank.
3. Missing child-process information is classified as unevaluable.
4. Missing parent-process information is classified as unevaluable.
5. Malformed XML is handled as a parsing error.
6. A non-Office parent launching PowerShell does not match this detection.

## Scope and Limitations

These are synthetic edge-case tests. They validate expected behavior for
the test inputs, but they do not establish that a real Office-to-scripting
process launch has been detected.

The current real-log review processed 3,133 Windows Security events and
reported zero matches, zero unevaluable events, and zero parsing errors.

A positive end-to-end detection remains unconfirmed. Additional validation
is needed to demonstrate a matching event from a controlled, authorized test.

The tests currently use synthetic inputs and a test-side implementation;
they should not be described as direct automated coverage of the production
script unless the production logic is explicitly invoked by the test suite.

## Conclusion

The synthetic edge-case test suite passed. Real-log findings remain
negative for the reviewed time window, and positive detection validation
is still outstanding.
