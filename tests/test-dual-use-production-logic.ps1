
# Tests the actual production detection function.
# Uses synthetic XML only; does not query Windows Security logs.

. .\detections\dual-use-tool-process-review.ps1

$passed = 0
$failed = 0

function New-TestEvent {
    param(
        [string]$Process,
        [string]$Parent = 'C:\Windows\explorer.exe',
        [string]$CommandLine = 'test-command',
        [string]$XmlOverride
    )

    if ($PSBoundParameters.ContainsKey('XmlOverride')) {
        $xml = $XmlOverride
    }
    else {
        $xml = "<Event><EventData>" +
            "<Data Name='NewProcessName'>$Process</Data>" +
            "<Data Name='ParentProcessName'>$Parent</Data>" +
            "<Data Name='TargetUserName'>TestUser</Data>" +
            "<Data Name='CommandLine'>$CommandLine</Data>" +
            "</EventData></Event>"
    }

    $eventObject = [PSCustomObject]@{
        TimeCreated = Get-Date
        XmlText = $xml
    }

    $eventObject | Add-Member -MemberType ScriptMethod -Name ToXml -Value {
        return $this.XmlText
    }

    return $eventObject
}

$tests = @(
    @{
        Name = 'CreatorProcessName fallback detects Office parent'
        Event = (New-TestEvent -XmlOverride "<Event><EventData><Data Name='NewProcessName'>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name='CreatorProcessName'>C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE</Data></EventData></Event>")
        ExpectedStatus = 'Alert'
        ExpectedPriority = 'Higher'
    },
    @{
        Name = 'Missing parent process does not create a Higher priority alert'
        Event = (New-TestEvent -XmlOverride "<Event><EventData><Data Name='NewProcessName'>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data></EventData></Event>")
        ExpectedStatus = 'Alert'
        ExpectedPriority = 'Low'
    },
    @{
        Name = 'PowerShell is detected'
        Event = (New-TestEvent -Process 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe')
        ExpectedStatus = 'Alert'
        ExpectedPriority = 'Low'
    },
    @{
        Name = 'Office launching PowerShell gets Higher priority'
        Event = (New-TestEvent -Process 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -Parent 'C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE')
        ExpectedStatus = 'Alert'
        ExpectedPriority = 'Higher'
    },
    @{
        Name = 'Notepad is not flagged'
        Event = (New-TestEvent -Process 'C:\Windows\System32\notepad.exe')
        ExpectedStatus = 'NoMatch'
        ExpectedPriority = ''
    },
    @{
        Name = 'Certutil is flagged with Low priority'
        Event = (New-TestEvent -Process 'C:\Windows\System32\certutil.exe')
        ExpectedStatus = 'Alert'
        ExpectedPriority = 'Low'
    },
    @{
        Name = 'Missing process path is unevaluable'
        Event = (New-TestEvent -XmlOverride "<Event><EventData><Data Name='CommandLine'>test</Data></EventData></Event>")
        ExpectedStatus = 'Unevaluable'
        ExpectedPriority = ''
    },
    @{
        Name = 'Malformed XML is reported as an error'
        Event = (New-TestEvent -XmlOverride '<Event><EventData>')
        ExpectedStatus = 'Error'
        ExpectedPriority = ''
    },
    @{
        Name = 'Recorded command line is marked Available'
        Event = (New-TestEvent -Process 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -CommandLine 'powershell.exe -NoProfile')
        ExpectedStatus = 'Alert'
        ExpectedPriority = 'Low'
        ExpectedCommandLineStatus = 'Available'
    },
    @{
        Name = 'Missing command line is marked Missing'
        Event = (New-TestEvent -XmlOverride "<Event><EventData><Data Name='NewProcessName'>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name='ParentProcessName'>C:\Windows\explorer.exe</Data><Data Name='TargetUserName'>TestUser</Data></EventData></Event>")
        ExpectedStatus = 'Alert'
        ExpectedPriority = 'Low'
        ExpectedCommandLineStatus = 'Missing'
    },
    @{
        Name = 'Whitespace-only command line is marked Missing'
        Event = (New-TestEvent -Process 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -CommandLine '   ')
        ExpectedStatus = 'Alert'
        ExpectedPriority = 'Low'
        ExpectedCommandLineStatus = 'Missing'
    }
)

foreach ($test in $tests) {
    $result = ConvertFrom-ProcessCreationEvent -EventRecord $test.Event

    $priority = ''
    if ($result.PSObject.Properties['Priority']) {
        $priority = [string]$result.Priority
    }

    $ok = (
        $result.Status -eq $test.ExpectedStatus -and
        $priority -eq $test.ExpectedPriority
    )

    if ($test.ContainsKey('ExpectedCommandLineStatus')) {
        $actualEvidenceStatus = ''
        if ($result.PSObject.Properties['CommandLineStatus']) {
            $actualEvidenceStatus = [string]$result.CommandLineStatus
        }

        $ok = $ok -and (
            $actualEvidenceStatus -eq $test.ExpectedCommandLineStatus
        )
    }

    if ($ok) {
        Write-Host "PASS: $($test.Name)" -ForegroundColor Green
        $passed++
    }
    else {
        $actualEvidenceStatus = ''
        if ($result.PSObject.Properties['CommandLineStatus']) {
            $actualEvidenceStatus = [string]$result.CommandLineStatus
        }

        Write-Host "FAIL: $($test.Name) - Status=$($result.Status), Priority=$priority, CommandLineStatus=$actualEvidenceStatus" -ForegroundColor Red
        $failed++
    }
}

Write-Host ''
Write-Host "Total: $($passed + $failed) | Passed: $passed | Failed: $failed"

if ($failed -gt 0) {
    throw 'One or more production-logic tests failed.'
}
