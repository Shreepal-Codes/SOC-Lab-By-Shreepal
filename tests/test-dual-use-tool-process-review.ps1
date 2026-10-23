
# Synthetic logic tests for dual-use tool review.
# These tests do not read or modify Windows Security logs.

$reviewTools = @(
    'powershell.exe', 'pwsh.exe', 'wscript.exe',
    'cscript.exe', 'mshta.exe', 'regsvr32.exe',
    'rundll32.exe', 'certutil.exe', 'bitsadmin.exe'
)

$officeProcesses = @(
    'winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe'
)

$scriptProcesses = @(
    'powershell.exe', 'pwsh.exe', 'wscript.exe',
    'cscript.exe', 'mshta.exe'
)

$cases = @(
    @{
        Name = 'PowerShell from Explorer is flagged for review'
        Parent = 'explorer.exe'
        Process = 'powershell.exe'
        ExpectedMatch = $true
        ExpectedPriority = 'Low'
    },
    @{
        Name = 'Office launching PowerShell gets higher priority'
        Parent = 'winword.exe'
        Process = 'powershell.exe'
        ExpectedMatch = $true
        ExpectedPriority = 'Higher'
    },
    @{
        Name = 'Certutil is flagged for review'
        Parent = 'cmd.exe'
        Process = 'certutil.exe'
        ExpectedMatch = $true
        ExpectedPriority = 'Low'
    },
    @{
        Name = 'Notepad is not flagged'
        Parent = 'explorer.exe'
        Process = 'notepad.exe'
        ExpectedMatch = $false
        ExpectedPriority = ''
    },
    @{
        Name = 'Office launching Notepad is not a script-pair alert'
        Parent = 'winword.exe'
        Process = 'notepad.exe'
        ExpectedMatch = $false
        ExpectedPriority = ''
    },
    @{
        Name = 'Office launching mshta gets higher priority'
        Parent = 'outlook.exe'
        Process = 'mshta.exe'
        ExpectedMatch = $true
        ExpectedPriority = 'Higher'
    }
)

$results = foreach ($case in $cases) {
    $matchedTool = $reviewTools -contains $case.Process
    $officeScriptPair = (
        ($officeProcesses -contains $case.Parent) -and
        ($scriptProcesses -contains $case.Process)
    )

    $priority = ''
    if ($matchedTool) {
        $priority = 'Low'
        if ($officeScriptPair) {
            $priority = 'Higher'
        }
    }

    $passed = (
        ($matchedTool -eq $case.ExpectedMatch) -and
        ($priority -eq $case.ExpectedPriority)
    )

    [PSCustomObject]@{
        Test = $case.Name
        ExpectedMatch = $case.ExpectedMatch
        ActualMatch = $matchedTool
        ExpectedPriority = $case.ExpectedPriority
        ActualPriority = $priority
        Result = if ($passed) { 'PASS' } else { 'FAIL' }
    }
}

$results | Format-Table -AutoSize

$passedCount = @($results | Where-Object Result -eq 'PASS').Count
$failedCount = @($results | Where-Object Result -eq 'FAIL').Count

"Total: $($results.Count) | Passed: $passedCount | Failed: $failedCount"

if ($failedCount -gt 0) {
    throw 'One or more synthetic logic tests failed.'
}
