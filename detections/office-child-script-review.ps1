# Detection: Office-launched scripting tool review
# Source: Windows Security Event ID 4688
# Severity: Review required; not proof of compromise

$lookbackHours = 24

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

$startTime = (Get-Date).AddHours(-$lookbackHours)

$events = @(
    Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = 4688
        StartTime = $startTime
    } -ErrorAction SilentlyContinue
)

Write-Host "4688 events retrieved: $($events.Count)"

if ($events.Count -eq 0) {
    Write-Host "No process-creation events found in the selected time window."
    exit
}

$alerts = foreach ($event in $events) {
    [xml]$xmlData = $event.ToXml()
    $fields = @{}

    foreach ($item in $xmlData.Event.EventData.Data) {
        $fields[$item.Name] = $item.'#text'
    }

    $processName = [System.IO.Path]::GetFileName(
        [string]$fields['NewProcessName']
    )

    $parentName = [System.IO.Path]::GetFileName(
        [string]$fields['ParentProcessName']
    )

    if (
        ($officeProcesses -contains $parentName) -and
        ($scriptProcesses -contains $processName)
    ) {
        [PSCustomObject]@{
            Time          = $event.TimeCreated
            Severity      = 'Review'
            ParentProcess = $parentName
            Process       = $processName
            User          = $fields['TargetUserName']
            CommandLine   = $fields['CommandLine']
            EventId       = 4688
            Reason        = 'Office application launched a scripting tool'
        }
    }
}

if ($alerts) {
    $alerts | Sort-Object Time -Descending | Format-List
} else {
    Write-Host "No Office-to-scripting-tool matches found in the last $lookbackHours hours."
}
