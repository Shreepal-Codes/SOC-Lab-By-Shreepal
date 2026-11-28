
$ErrorActionPreference = 'Stop'

. "G:\SOC-Investigation-Lab\analysis\process-ancestry-analysis.ps1"
. "G:\SOC-Investigation-Lab\analysis\process-ancestry-reconstruction.ps1"

$script:Passed = 0
$script:Failed = 0

function Write-TestResult {
    param(
        [string]$Name,
        [bool]$Condition
    )

    if ($Condition) {
        $script:Passed++
        Write-Host "[PASS] $Name" -ForegroundColor Green
    }
    else {
        $script:Failed++
        Write-Host "[FAIL] $Name" -ForegroundColor Red
    }
}

function New-TestEvent {
    param(
        [int]$EventId,
        [string]$RecordId,
        [string]$Time,
        [string]$ProcessId,
        [string]$ProcessName,
        [string]$ParentProcessId = '0',
        [string]$ParentProcessName = ''
    )

    $isCreation = $EventId -eq 4688

    [PSCustomObject]@{
        EventId          = $EventId
        EventRecordId    = $RecordId
        TimeCreatedUtc   = [DateTimeOffset]::Parse($Time)
        ProcessId        = [uint64]$ProcessId
        ParentProcessId  = if ($isCreation) {
            [uint64]$ParentProcessId
        } else {
            $null
        }
        ProcessName      = $ProcessName
        ParentProcessName = $ParentProcessName
        CommandLine      = $null
        Status           = $null
        EventType        = if ($isCreation) {
            'Creation'
        } else {
            'Termination'
        }
    }
}

$base = [DateTimeOffset]::Parse('2026-11-28T10:00:00Z')

# Test 1: One unique parent instance.
$events = @(
    (New-TestEvent 4688 '1' $base.ToString('o') '100' 'C:\Windows\explorer.exe' '50' 'C:\Windows\winlogon.exe')
    (New-TestEvent 4688 '2' $base.AddSeconds(5).ToString('o') '200' 'C:\Windows\System32\cmd.exe' '100' 'C:\Windows\explorer.exe')
)

$result = Invoke-ProcessAncestryReconstruction -Events $events

$cmdRelationship = $result.Relationships |
    Where-Object { $_.ChildProcessId -eq 200 }

Write-TestResult 'Unique parent relationship confirmed' (
    $cmdRelationship.RelationshipStatus -eq 'Confirmed' -and
    $cmdRelationship.ParentProcessId -eq 100
)

# Test 2: Parent process not observed.
$events = @(
    (New-TestEvent 4688 '3' $base.ToString('o') '300' 'C:\Windows\System32\powershell.exe' '999' 'C:\Windows\explorer.exe')
)

$result = Invoke-ProcessAncestryReconstruction -Events $events

Write-TestResult 'Missing parent reported as unresolved' (
    $result.UnresolvedRelationships.Count -eq 1 -and
    $result.UnresolvedRelationships[0].Reason -eq 'ParentProcessNotObserved'
)

# Test 3: Parent terminated before child creation.
$events = @(
    (New-TestEvent 4688 '4' $base.ToString('o') '400' 'C:\Windows\explorer.exe' '50' 'C:\Windows\winlogon.exe')
    (New-TestEvent 4689 '5' $base.AddSeconds(2).ToString('o') '400' 'C:\Windows\explorer.exe')
    (New-TestEvent 4688 '6' $base.AddSeconds(5).ToString('o') '401' 'C:\Windows\System32\cmd.exe' '400' 'C:\Windows\explorer.exe')
)

$result = Invoke-ProcessAncestryReconstruction -Events $events

Write-TestResult 'Parent terminated before child creation is unresolved' (
    $result.Relationships |
        Where-Object {
            $_.ChildProcessId -eq 401 -and
            $_.RelationshipStatus -eq 'Unresolved' -and
            $_.Reason -eq 'NoParentInstanceActiveAtChildCreation'
        } |
        Measure-Object |
        Select-Object -ExpandProperty Count
)

# Test 4: PID reuse with only one valid parent instance.
$events = @(
    (New-TestEvent 4688 '10' $base.ToString('o') '500' 'C:\Windows\explorer.exe' '50' 'C:\Windows\winlogon.exe')
    (New-TestEvent 4689 '11' $base.AddSeconds(3).ToString('o') '500' 'C:\Windows\explorer.exe')
    (New-TestEvent 4688 '12' $base.AddSeconds(4).ToString('o') '500' 'C:\Windows\notepad.exe' '50' 'C:\Windows\winlogon.exe')
    (New-TestEvent 4688 '13' $base.AddSeconds(5).ToString('o') '501' 'C:\Windows\System32\cmd.exe' '500' 'C:\Windows\notepad.exe')
)

$result = Invoke-ProcessAncestryReconstruction -Events $events

$childRelationship = $result.Relationships |
    Where-Object { $_.ChildProcessId -eq 501 }

Write-TestResult 'PID reuse selects the parent instance active at child creation' (
    $childRelationship.RelationshipStatus -eq 'Confirmed' -and
    $childRelationship.ParentProcessName -like '*notepad.exe'
)

# Test 5: Duplicate parent creation makes parent PID ambiguous.
$events = @(
    (New-TestEvent 4688 '20' $base.ToString('o') '600' 'C:\Windows\explorer.exe' '50' 'C:\Windows\winlogon.exe')
    (New-TestEvent 4688 '21' $base.AddSeconds(1).ToString('o') '600' 'C:\Windows\explorer.exe' '50' 'C:\Windows\winlogon.exe')
    (New-TestEvent 4688 '22' $base.AddSeconds(2).ToString('o') '601' 'C:\Windows\System32\cmd.exe' '600' 'C:\Windows\explorer.exe')
)

$result = Invoke-ProcessAncestryReconstruction -Events $events

$childRelationship = $result.Relationships |
    Where-Object { $_.ChildProcessId -eq 601 }

Write-TestResult 'Ambiguous parent instances are not silently selected' (
    $childRelationship.RelationshipStatus -eq 'Ambiguous'
)

# Test 6: Parent name mismatch.
$events = @(
    (New-TestEvent 4688 '30' $base.ToString('o') '700' 'C:\Windows\explorer.exe' '50' 'C:\Windows\winlogon.exe')
    (New-TestEvent 4688 '31' $base.AddSeconds(1).ToString('o') '701' 'C:\Windows\System32\cmd.exe' '700' 'C:\Windows\notepad.exe')
)

$result = Invoke-ProcessAncestryReconstruction -Events $events

Write-TestResult 'Parent name mismatch generates anomaly' (
    $result.Anomalies |
        Where-Object { $_.Type -eq 'ParentProcessNameMismatch' } |
        Measure-Object |
        Select-Object -ExpandProperty Count
)

# Test 7: Self-referencing parent PID.
$events = @(
    (New-TestEvent 4688 '40' $base.ToString('o') '800' 'C:\Windows\System32\cmd.exe' '800' 'C:\Windows\System32\cmd.exe')
)

$result = Invoke-ProcessAncestryReconstruction -Events $events

Write-TestResult 'Self-referencing process is flagged' (
    $result.Relationships[0].RelationshipStatus -eq 'SelfReference' -and
    $result.Anomalies.Type -contains 'SelfReferencingProcess'
)

# Test 8: Parent created after child.
$events = @(
    (New-TestEvent 4688 '50' $base.ToString('o') '901' 'C:\Windows\System32\cmd.exe' '900' 'C:\Windows\explorer.exe')
    (New-TestEvent 4688 '51' $base.AddSeconds(5).ToString('o') '900' 'C:\Windows\explorer.exe' '50' 'C:\Windows\winlogon.exe')
)

$result = Invoke-ProcessAncestryReconstruction -Events $events

Write-TestResult 'Parent created after child is not accepted' (
    $result.Relationships |
        Where-Object {
            $_.ChildProcessId -eq 901 -and
            $_.RelationshipStatus -eq 'Unresolved'
        } |
        Measure-Object |
        Select-Object -ExpandProperty Count
)

Write-Host "`n==============================="
Write-Host "Ancestry Reconstruction Results"
Write-Host "==============================="
Write-Host "Passed: $script:Passed" -ForegroundColor Green
Write-Host "Failed: $script:Failed" -ForegroundColor Red
Write-Host "Total:  $($script:Passed + $script:Failed)"

if ($script:Failed -gt 0) {
    exit 1
}
