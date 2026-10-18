
# Office-to-Scripting-Tool Process Review
# Reads Security Event ID 4688; does not execute or block processes.

$ErrorActionPreference = 'Stop'
$startTime = (Get-Date).AddHours(-24)

$officeProcesses = @(
    'winword.exe',
    'excel.exe',
    'powerpnt.exe',
    'outlook.exe'
)

$scriptProcesses = @(
    'powershell.exe',
    'pwsh.exe',
    'wscript.exe',
    'cscript.exe',
    'mshta.exe'
)

Write-Host "Office-to-Scripting-Tool Process Review"
Write-Host "Window start: $startTime"
Write-Host ""

try {
    $events = @(
        Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = 4688
            StartTime = $startTime
        } -ErrorAction Stop
    )
}
catch {
    Write-Host "ERROR: Could not read Security Event 4688."
    Write-Host "Details: $($_.Exception.Message)"
    Write-Host "Try running PowerShell as Administrator."
    exit 1
}

Write-Host "Events retrieved: $($events.Count)"

if ($events.Count -eq 0) {
    Write-Host "No Event 4688 records were found in this window."
    Write-Host "No detection conclusion can be drawn from an empty result."
    exit 0
}

$parsed = foreach ($event in $events) {
    try {
        [xml]$xmlData = $event.ToXml()
        $fields = @{}

        foreach ($item in $xmlData.Event.EventData.Data) {
            $fields[$item.GetAttribute('Name')] = $item.InnerText
        }

        $childPath = [string]$fields['NewProcessName']

        # Prefer ParentProcessName, with CreatorProcessName as fallback.
        $parentPath = [string]$fields['ParentProcessName']
        if ([string]::IsNullOrWhiteSpace($parentPath)) {
            $parentPath = [string]$fields['CreatorProcessName']
        }

        $child = if (-not [string]::IsNullOrWhiteSpace($childPath)) {
            [System.IO.Path]::GetFileName($childPath)
        } else {
            $null
        }

        $parent = if (-not [string]::IsNullOrWhiteSpace($parentPath)) {
            [System.IO.Path]::GetFileName($parentPath)
        } else {
            $null
        }

        $status = if (
            [string]::IsNullOrWhiteSpace($child) -or
            [string]::IsNullOrWhiteSpace($parent)
        ) {
            'Unevaluable'
        } else {
            'Evaluated'
        }

        $isMatch = $false
        if ($status -eq 'Evaluated') {
            $isMatch = (
                ($officeProcesses -contains $parent) -and
                ($scriptProcesses -contains $child)
            )
        }

        [PSCustomObject]@{
            Time       = $event.TimeCreated
            EventId    = $event.Id
            Parent     = $parent
            Child      = $child
            CommandLine = [string]$fields['CommandLine']
            Status     = $status
            IsMatch    = $isMatch
        }
    }
    catch {
        [PSCustomObject]@{
            Time        = $event.TimeCreated
            EventId     = $event.Id
            Parent      = $null
            Child       = $null
            CommandLine = $null
            Status      = 'ParseError'
            IsMatch     = $false
        }
    }
}

$matches = @($parsed | Where-Object {
    $_.Status -eq 'Evaluated' -and $_.IsMatch
})

$unevaluable = @($parsed | Where-Object {
    $_.Status -eq 'Unevaluable' -or $_.Status -eq 'ParseError'
})

Write-Host ""
Write-Host "--- Summary ---"
Write-Host "Events retrieved: $($events.Count)"
Write-Host "Events processed: $($parsed.Count)"
Write-Host "Evaluated events: $( @($parsed | Where-Object Status -eq 'Evaluated').Count )"
Write-Host "Unevaluable / parse-error events: $($unevaluable.Count)"
Write-Host "Office-to-scripting-tool matches: $($matches.Count)"

if ($matches.Count -gt 0) {
    Write-Host ""
    Write-Host "--- Matches requiring investigation ---"
    $matches |
        Select-Object Time, Parent, Child, CommandLine |
        Format-Table -AutoSize
}
else {
    Write-Host ""
    Write-Host "No matching process relationships found in this window."
}

if ($unevaluable.Count -gt 0) {
    Write-Host ""
    Write-Host "--- Sample unevaluable records ---"
    $unevaluable |
        Select-Object -First 10 Time, Parent, Child, Status |
        Format-Table -AutoSize
}

Write-Host ""
Write-Host "Review matches in context; a match is not proof of malicious activity."
