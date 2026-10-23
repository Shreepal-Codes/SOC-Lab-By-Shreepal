# Detection: Dual-Use Windows Tool Review
# Purpose: Flag selected process executions for analyst review.
# Source: Windows Security Event ID 4688

$lookbackHours = 24

$reviewTools = @(
    'powershell.exe',
    'pwsh.exe',
    'wscript.exe',
    'cscript.exe',
    'mshta.exe',
    'regsvr32.exe',
    'rundll32.exe',
    'certutil.exe',
    'bitsadmin.exe'
)

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

$events = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4688
    StartTime = $startTime
} -ErrorAction SilentlyContinue

$alerts = foreach ($event in $events) {
    [xml]$xmlData = $event.ToXml()
    $fields = @{}

    foreach ($item in $xmlData.Event.EventData.Data) {
        $fields[$item.Name] = $item.'#text'
    }

    $processPath = [string]$fields['NewProcessName']
    $parentPath  = [string]$fields['ParentProcessName']

    $processName = [System.IO.Path]::GetFileName($processPath)
    $parentName  = [System.IO.Path]::GetFileName($parentPath)

    $matchedTool = $reviewTools -contains $processName
    $officeScriptPair = (
        ($officeProcesses -contains $parentName) -and
        ($scriptProcesses -contains $processName)
    )

    if ($matchedTool) {
        $reason = 'Review: selected dual-use Windows tool executed'
        $priority = 'Low'

        if ($officeScriptPair) {
            $reason = 'Review: Office process launched a scripting tool'
            $priority = 'Higher'
        }

        [PSCustomObject]@{
            Time          = $event.TimeCreated
            Priority      = $priority
            Process       = $processPath
            ParentProcess = $parentPath
            User          = $fields['TargetUserName']
            CommandLine   = $fields['CommandLine']
            Reason        = $reason
            EventId       = 4688
        }
    }
}

if ($alerts) {
    $alerts |
        Sort-Object Time -Descending |
        Format-List
} else {
    Write-Host "No matching process events found in the last $lookbackHours hours."
}
