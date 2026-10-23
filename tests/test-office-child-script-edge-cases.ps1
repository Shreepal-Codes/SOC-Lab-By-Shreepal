# Synthetic edge-case tests for Event ID 4688 field extraction
# Synthetic XML only: this script does not create Security events or launch processes.
$ErrorActionPreference = 'Stop'

$officeProcesses = @('winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe')
$scriptProcesses = @('powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe')

function Convert-4688XmlToDetectionRecord {
    param([Parameter(Mandatory)][string]$Xml)

    try {
        [xml]$xmlData = $Xml
        $fields = @{}
        foreach ($item in $xmlData.Event.EventData.Data) {
            $fields[$item.GetAttribute('Name')] = $item.InnerText
        }

        $childPath = [string]$fields['NewProcessName']
        $parentPath = [string]$fields['ParentProcessName']
        if ([string]::IsNullOrWhiteSpace($parentPath)) {
            $parentPath = [string]$fields['CreatorProcessName']
        }

        $child = if (-not [string]::IsNullOrWhiteSpace($childPath)) {
            [System.IO.Path]::GetFileName($childPath)
        } else { $null }

        $parent = if (-not [string]::IsNullOrWhiteSpace($parentPath)) {
            [System.IO.Path]::GetFileName($parentPath)
        } else { $null }

        $status = if ([string]::IsNullOrWhiteSpace($child) -or
                      [string]::IsNullOrWhiteSpace($parent)) {
            'Unevaluable'
        } else { 'Evaluated' }

        $isMatch = $false
        if ($status -eq 'Evaluated') {
            $isMatch = (($officeProcesses -contains $parent.ToLowerInvariant()) -and
                        ($scriptProcesses -contains $child.ToLowerInvariant()))
        }

        [pscustomobject]@{
            Parent = $parent
            Child = $child
            Status = $status
            IsMatch = $isMatch
            ErrorType = $null
        }
    }
    catch {
        [pscustomobject]@{
            Parent = $null
            Child = $null
            Status = 'ParseError'
            IsMatch = $false
            ErrorType = $_.Exception.GetType().Name
        }
    }
}

function New-TestEventXml {
    param([string]$DataXml)
    return @"
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><EventID>4688</EventID></System>
  <EventData>$DataXml</EventData>
</Event>
"@
}

$tests = @(
    @{
        Name = 'ParentProcessName takes precedence over CreatorProcessName'
        Xml = (New-TestEventXml '<Data Name="NewProcessName">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name="ParentProcessName">C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE</Data><Data Name="CreatorProcessName">C:\Windows\explorer.exe</Data>')
        ExpectedStatus = 'Evaluated'; ExpectedMatch = $true; ExpectedParent = 'WINWORD.EXE'
    },
    @{
        Name = 'CreatorProcessName fallback detects Office parent'
        Xml = (New-TestEventXml '<Data Name="NewProcessName">C:\Windows\System32\wscript.exe</Data><Data Name="ParentProcessName"></Data><Data Name="CreatorProcessName">C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE</Data>')
        ExpectedStatus = 'Evaluated'; ExpectedMatch = $true; ExpectedParent = 'OUTLOOK.EXE'
    },
    @{
        Name = 'Missing child path is unevaluable'
        Xml = (New-TestEventXml '<Data Name="ParentProcessName">C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE</Data>')
        ExpectedStatus = 'Unevaluable'; ExpectedMatch = $false; ExpectedParent = 'WINWORD.EXE'
    },
    @{
        Name = 'Missing parent fields are unevaluable'
        Xml = (New-TestEventXml '<Data Name="NewProcessName">C:\Windows\System32\powershell.exe</Data>')
        ExpectedStatus = 'Unevaluable'; ExpectedMatch = $false; ExpectedParent = $null
    },
    @{
        Name = 'Malformed XML is classified as parse error'
        Xml = '<Event><EventData><Data Name="NewProcessName">oops'
        ExpectedStatus = 'ParseError'; ExpectedMatch = $false; ExpectedParent = $null
    },
    @{
        Name = 'Non-Office parent with script child does not match'
        Xml = (New-TestEventXml '<Data Name="NewProcessName">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name="ParentProcessName">C:\Windows\explorer.exe</Data>')
        ExpectedStatus = 'Evaluated'; ExpectedMatch = $false; ExpectedParent = 'explorer.exe'
    }
)

$failed = 0
$results = foreach ($test in $tests) {
    $actual = Convert-4688XmlToDetectionRecord -Xml $test.Xml
    $pass = ($actual.Status -eq $test.ExpectedStatus) -and
            ($actual.IsMatch -eq $test.ExpectedMatch) -and
            ($actual.Parent -eq $test.ExpectedParent)

    if (-not $pass) { $failed++ }
    [pscustomobject]@{
        Test = $test.Name
        Result = if ($pass) { 'PASS' } else { 'FAIL' }
        ExpectedStatus = $test.ExpectedStatus
        ActualStatus = $actual.Status
        ExpectedMatch = $test.ExpectedMatch
        ActualMatch = $actual.IsMatch
        ActualParent = $actual.Parent
        ErrorType = $actual.ErrorType
    }
}

$results | Format-Table -Wrap -AutoSize
Write-Host ""
Write-Host "Tests total: $($tests.Count)"
Write-Host "Passed: $($tests.Count - $failed)"
Write-Host "Failed: $failed"
if ($failed -gt 0) { exit 1 }
