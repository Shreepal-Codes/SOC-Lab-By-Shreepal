
# Detection: Dual-Use Windows Tool Review
# Purpose: Flag selected process executions for analyst review.
# Source: Windows Security Event ID 4688

$script:LookbackHours = 24

$script:ReviewTools = @(
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

$script:OfficeProcesses = @(
    'winword.exe',
    'excel.exe',
    'powerpnt.exe',
    'outlook.exe'
)

$script:ScriptProcesses = @(
    'powershell.exe',
    'pwsh.exe',
    'wscript.exe',
    'cscript.exe',
    'mshta.exe'
)

function ConvertFrom-ProcessCreationEvent {
    param(
        [Parameter(Mandatory = $true)]
        $EventRecord
    )

    try {
        [xml]$xmlData = $EventRecord.ToXml()
        $fields = @{}

        foreach ($item in $xmlData.Event.EventData.Data) {
            $fields[[string]$item.Name] = [string]$item.'#text'
        }

        $processPath = [string]$fields['NewProcessName']

        # Windows event versions may expose different parent-process fields.
        $parentPath = [string]$fields['ParentProcessName']

        if ([string]::IsNullOrWhiteSpace($parentPath)) {
            $parentPath = [string]$fields['CreatorProcessName']
        }

        # Explicitly identify whether command-line evidence is present.
        $commandLine = [string]$fields['CommandLine']
        $commandLineStatus = 'Available'

        if ([string]::IsNullOrWhiteSpace($commandLine)) {
            $commandLineStatus = 'Missing'
        }

        if ([string]::IsNullOrWhiteSpace($processPath)) {
            return [PSCustomObject]@{
                Status = 'Unevaluable'
                Reason = 'Missing NewProcessName field'
            }
        }

        $processName = [System.IO.Path]::GetFileName($processPath)
        $parentName = [System.IO.Path]::GetFileName($parentPath)

        $matchedTool = $script:ReviewTools -contains $processName

        $officeScriptPair = (
            ($script:OfficeProcesses -contains $parentName) -and
            ($script:ScriptProcesses -contains $processName)
        )

        if (-not $matchedTool) {
            return [PSCustomObject]@{
                Status = 'NoMatch'
                Reason = 'Process is not in the review list'
            }
        }

        $priority = 'Low'
        $reason = 'Review: selected dual-use Windows tool executed'

        if ($officeScriptPair) {
            $priority = 'Higher'
            $reason = 'Review: Office process launched a scripting tool'
        }

        return [PSCustomObject]@{
            Status            = 'Alert'
            Time              = $EventRecord.TimeCreated
            Priority          = $priority
            Process           = $processPath
            ParentProcess     = $parentPath
            User              = $fields['TargetUserName']
            CommandLine       = $commandLine
            CommandLineStatus = $commandLineStatus
            Reason            = $reason
            EventId           = 4688
        }
    }
    catch {
        return [PSCustomObject]@{
            Status = 'Error'
            Reason = $_.Exception.Message
        }
    }
}

function Invoke-DualUseToolDetection {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Events
    )

    foreach ($eventRecord in $Events) {
        ConvertFrom-ProcessCreationEvent -EventRecord $eventRecord
    }
}

# Dot-sourcing this file loads its functions for testing.
# Run the script normally to query recent Windows Security events.
if ($MyInvocation.InvocationName -ne '.') {
    $startTime = (Get-Date).AddHours(-$script:LookbackHours)

    try {
        $events = @(
            Get-WinEvent -FilterHashtable @{
                LogName   = 'Security'
                Id        = 4688
                StartTime = $startTime
            } -ErrorAction Stop
        )

        $results = @(Invoke-DualUseToolDetection -Events $events)
        $alerts = @($results | Where-Object Status -eq 'Alert')
        $unevaluable = @($results | Where-Object Status -eq 'Unevaluable')
        $errors = @($results | Where-Object Status -eq 'Error')

        if ($alerts.Count -gt 0) {
            $alerts |
                Sort-Object Time -Descending |
                Select-Object Time, Priority, Process, ParentProcess,
                    User, CommandLine, CommandLineStatus, Reason, EventId |
                Format-List
        }
        else {
            Write-Host "No matching process events found in the last $script:LookbackHours hours."
        }

        Write-Host "Events processed: $($results.Count)"
        Write-Host "Alerts: $($alerts.Count)"
        Write-Host "Unevaluable: $($unevaluable.Count)"
        Write-Host "Errors: $($errors.Count)"
    }
    catch {
        Write-Error "Could not query Windows Security events. Check permissions and audit-log availability. Details: $($_.Exception.Message)"
    }
}
