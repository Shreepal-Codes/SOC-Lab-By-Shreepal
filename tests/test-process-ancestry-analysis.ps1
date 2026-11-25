
. "$PSScriptRoot\..\analysis\process-ancestry-analysis.ps1"

$passed = 0
$failed = 0

function Write-TestResult {
    param(
        [string]$Name,
        [bool]$Success,
        [string]$Details = ''
    )

    if ($Success) {
        Write-Host "PASS: $Name" -ForegroundColor Green
        $script:passed++
    }
    else {
        Write-Host "FAIL: $Name $Details" -ForegroundColor Red
        $script:failed++
    }
}

function Test-ProcessId {
    param(
        [string]$Name,
        [string]$InputId,
        [UInt64]$Expected
    )

    try {
        $actual = ConvertTo-NormalizedProcessId -ProcessId $InputId
        Write-TestResult -Name $Name -Success ($actual -eq $Expected) `
            -Details "(Expected $Expected, got $actual)"
    }
    catch {
        Write-TestResult -Name $Name -Success $false `
            -Details $_.Exception.Message
    }
}

function Test-InvalidProcessId {
    param(
        [string]$Name,
        [string]$InputId
    )

    try {
        ConvertTo-NormalizedProcessId -ProcessId $InputId | Out-Null
        Write-TestResult -Name $Name -Success $false `
            -Details '(Expected an error)'
    }
    catch {
        Write-TestResult -Name $Name -Success $true
    }
}

function New-LifecycleTestEvent {
    param(
        [string]$EventType,
        [UInt64]$ProcessId,
        [string]$ProcessName,
        [string]$Time,
        [string]$RecordId,
        [UInt64]$ParentProcessId = 0
    )

    return [PSCustomObject]@{
        EventId = if ($EventType -eq 'Creation') { 4688 } else { 4689 }
        EventRecordId = $RecordId
        TimeCreatedUtc = [DateTimeOffset]::Parse($Time)
        ProcessId = $ProcessId
        ParentProcessId = if ($EventType -eq 'Creation') {
            $ParentProcessId
        } else {
            $null
        }
        ProcessName = $ProcessName
        ParentProcessName = $null
        CommandLine = $null
        Status = if ($EventType -eq 'Termination') { '0x0' } else { $null }
        EventType = $EventType
    }
}


Write-Host "`n--- Process ID Normalization Tests ---" -ForegroundColor Cyan

Test-ProcessId "Hexadecimal PID converts correctly" "0x441c" 17436
Test-ProcessId "Decimal PID remains consistent" "17436" 17436
Test-ProcessId "Uppercase hexadecimal is accepted" "0X441C" 17436
Test-ProcessId "Leading and trailing spaces are handled" " 0x441c " 17436
Test-ProcessId "Zero PID is accepted" "0x0" 0

Test-InvalidProcessId "Invalid text is rejected" "not-a-pid"
Test-InvalidProcessId "Malformed hexadecimal is rejected" "0xGG"
Test-InvalidProcessId "Negative PID is rejected" "-17436"
Test-InvalidProcessId "Empty PID is rejected" ""


Write-Host "`n--- Event Parser Tests ---" -ForegroundColor Cyan

$creationXml = @'
<Event>
    <System>
        <EventID>4688</EventID>
        <TimeCreated SystemTime="2026-11-25T17:35:02.0457039Z"/>
        <EventRecordID>2430267</EventRecordID>
    </System>
    <EventData>
        <Data Name="NewProcessId">0x9620</Data>
        <Data Name="NewProcessName">C:\Windows\System32\AcerHardwareService.exe</Data>
        <Data Name="ProcessId">0x1228</Data>
        <Data Name="ParentProcessName">C:\Windows\System32\AcerCentralService.exe</Data>
        <Data Name="CommandLine"></Data>
    </EventData>
</Event>
'@

$terminationXml = @'
<Event>
    <System>
        <EventID>4689</EventID>
        <TimeCreated SystemTime="2026-11-25T17:36:33.5411502Z"/>
        <EventRecordID>2430280</EventRecordID>
    </System>
    <EventData>
        <Data Name="Status">0x0</Data>
        <Data Name="ProcessId">0xa48c</Data>
        <Data Name="ProcessName">C:\Program Files\Microsoft\Edge\identity_helper.exe</Data>
    </EventData>
</Event>
'@

try {
    $creation = ConvertFrom-ProcessLifecycleEvent -EventXml $creationXml

    Write-TestResult "Creation event parsing" (
        $creation.EventId -eq 4688 -and
        $creation.ProcessId -eq 38432 -and
        $creation.ParentProcessId -eq 4648 -and
        $creation.EventType -eq 'Creation'
    )
}
catch {
    Write-TestResult "Creation event parsing" $false $_.Exception.Message
}

try {
    $termination = ConvertFrom-ProcessLifecycleEvent -EventXml $terminationXml

    Write-TestResult "Termination event parsing" (
        $termination.EventId -eq 4689 -and
        $termination.ProcessId -eq 42124 -and
        $termination.Status -eq '0x0' -and
        $termination.EventType -eq 'Termination'
    )
}
catch {
    Write-TestResult "Termination event parsing" $false $_.Exception.Message
}

try {
    ConvertFrom-ProcessLifecycleEvent -EventXml '<Event><System><EventID>9999</EventID></System></Event>' | Out-Null
    Write-TestResult "Unsupported event ID rejected" $false
}
catch {
    Write-TestResult "Unsupported event ID rejected" $true
}

try {
    ConvertFrom-ProcessLifecycleEvent -EventXml '<InvalidXml>' | Out-Null
    Write-TestResult "Malformed XML rejected" $false
}
catch {
    Write-TestResult "Malformed XML rejected" $true
}


Write-Host "`n--- Process Lifetime Correlation Tests ---" -ForegroundColor Cyan

$notepad = 'C:\Windows\System32\notepad.exe'
$explorer = 'C:\Windows\explorer.exe'

# Test 14: Creation and termination match; lifetime is five minutes.
$events = @(
    (New-LifecycleTestEvent Creation 4660 $notepad '2026-11-25T10:00:00Z' '1001' 1000)
    (New-LifecycleTestEvent Termination 4660 $notepad '2026-11-25T10:05:00Z' '1002')
)

$result = Invoke-ProcessLifetimeCorrelation -Events $events
$instance = $result.ProcessInstances[0]

Write-TestResult "Five-minute process lifetime calculated" (
    $instance.Status -eq 'Matched' -and
    $instance.Lifetime.TotalMinutes -eq 5
)


# Test 15: Creation without termination remains unconfirmed.
$events = @(
    (New-LifecycleTestEvent Creation 5000 $notepad '2026-11-25T10:00:00Z' '2001' 1000)
)

$result = Invoke-ProcessLifetimeCorrelation -Events $events

Write-TestResult "Creation without termination is reported" (
    $result.ProcessInstances.Count -eq 1 -and
    $result.ProcessInstances[0].Status -eq 'NoTerminationObserved' -and
    $null -eq $result.ProcessInstances[0].TerminatedAt
)


# Test 16: Termination without creation is unmatched.
$events = @(
    (New-LifecycleTestEvent Termination 6000 $notepad '2026-11-25T10:05:00Z' '3001')
)

$result = Invoke-ProcessLifetimeCorrelation -Events $events

Write-TestResult "Unmatched termination is reported" (
    $result.UnmatchedTerminations.Count -eq 1 -and
    $result.ProcessInstances.Count -eq 0
)


# Test 17: Reused PID creates two separate process instances.
$events = @(
    (New-LifecycleTestEvent Creation 7000 $notepad '2026-11-25T10:00:00Z' '4001' 1000)
    (New-LifecycleTestEvent Termination 7000 $notepad '2026-11-25T10:01:00Z' '4002')
    (New-LifecycleTestEvent Creation 7000 $explorer '2026-11-25T10:02:00Z' '4003' 1000)
    (New-LifecycleTestEvent Termination 7000 $explorer '2026-11-25T10:04:00Z' '4004')
)

$result = Invoke-ProcessLifetimeCorrelation -Events $events

Write-TestResult "PID reuse creates separate process instances" (
    $result.ProcessInstances.Count -eq 2 -and
    $result.ProcessInstances[0].Status -eq 'Matched' -and
    $result.ProcessInstances[1].Status -eq 'Matched' -and
    $result.ProcessInstances[0].Lifetime.TotalMinutes -eq 1 -and
    $result.ProcessInstances[1].Lifetime.TotalMinutes -eq 2
)


# Test 18: Duplicate creation for an active PID is ambiguous.
$events = @(
    (New-LifecycleTestEvent Creation 8000 $notepad '2026-11-25T10:00:00Z' '5001' 1000)
    (New-LifecycleTestEvent Creation 8000 $notepad '2026-11-25T10:01:00Z' '5002' 1000)
)

$result = Invoke-ProcessLifetimeCorrelation -Events $events

Write-TestResult "Duplicate process creation is flagged as ambiguous" (
    $result.ProcessInstances.Count -eq 2 -and
    $result.ProcessInstances[0].Status -eq 'AmbiguousDuplicateCreation' -and
    $result.ProcessInstances[1].Status -eq 'AmbiguousDuplicateCreation' -and
    $result.Anomalies.Count -eq 1
)


# Test 19: Different process names are not silently matched.
$events = @(
    (New-LifecycleTestEvent Creation 9000 $notepad '2026-11-25T10:00:00Z' '6001' 1000)
    (New-LifecycleTestEvent Termination 9000 $explorer '2026-11-25T10:05:00Z' '6002')
)

$result = Invoke-ProcessLifetimeCorrelation -Events $events

Write-TestResult "Process name mismatch is flagged" (
    $result.ProcessInstances[0].Status -eq 'ProcessNameMismatch' -and
    $result.Anomalies.Count -eq 1
)


# Test 20: Out-of-order input is sorted before correlation.
$events = @(
    (New-LifecycleTestEvent Termination 10000 $notepad '2026-11-25T10:05:00Z' '7002')
    (New-LifecycleTestEvent Creation 10000 $notepad '2026-11-25T10:00:00Z' '7001' 1000)
)

$result = Invoke-ProcessLifetimeCorrelation -Events $events

Write-TestResult "Out-of-order events are sorted before correlation" (
    $result.ProcessInstances.Count -eq 1 -and
    $result.ProcessInstances[0].Status -eq 'Matched' -and
    $result.ProcessInstances[0].Lifetime.TotalMinutes -eq 5
)


Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "FINAL TEST RESULTS" -ForegroundColor Cyan
Write-Host "Total:  $($passed + $failed)"
Write-Host "Passed: $passed" -ForegroundColor Green
Write-Host "Failed: $failed" -ForegroundColor Red
Write-Host "========================================" -ForegroundColor Cyan

if ($failed -gt 0) {
    exit 1
}
