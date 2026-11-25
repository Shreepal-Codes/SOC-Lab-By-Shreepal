
function ConvertTo-NormalizedProcessId {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProcessId
    )

    $normalizedId = $ProcessId.Trim()

    if ([string]::IsNullOrWhiteSpace($normalizedId)) {
        throw "Process ID cannot be empty."
    }

    if ($normalizedId -match '^0[xX][0-9a-fA-F]+$') {
        return [Convert]::ToUInt64($normalizedId.Substring(2), 16)
    }

    if ($normalizedId -match '^[0-9]+$') {
        return [Convert]::ToUInt64($normalizedId, 10)
    }

    throw "Invalid process ID format: $ProcessId"
}


function ConvertFrom-ProcessLifecycleEvent {
    param(
        [Parameter(Mandatory = $true)]
        [string]$EventXml
    )

    try {
        [xml]$xml = $EventXml

        $namespace = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
        $namespace.AddNamespace(
            'e',
            'http://schemas.microsoft.com/win/2004/08/events/event'
        )

        $systemNode = $xml.SelectSingleNode(
            "/*[local-name()='Event']/*[local-name()='System']"
        )

        $eventId = [int]$systemNode.SelectSingleNode(
            "*[local-name()='EventID']"
        ).InnerText

        $timestamp = $systemNode.SelectSingleNode(
            "*[local-name()='TimeCreated']"
        ).GetAttribute('SystemTime')

        $recordNode = $systemNode.SelectSingleNode(
            "*[local-name()='EventRecordID']"
        )

        $recordId = if ($null -ne $recordNode) {
            $recordNode.InnerText
        }
        else {
            $null
        }

        $fields = @{}

        $dataNodes = $xml.SelectNodes(
            "/*[local-name()='Event']/*[local-name()='EventData']/*[local-name()='Data']"
        )

        foreach ($data in $dataNodes) {
            $fields[$data.GetAttribute('Name')] = $data.InnerText
        }

        $parsedTime = [DateTimeOffset]::Parse(
            $timestamp,
            [Globalization.CultureInfo]::InvariantCulture
        ).ToUniversalTime()

        if ($eventId -eq 4688) {
            $requiredFields = @(
                'NewProcessId',
                'ProcessId',
                'NewProcessName'
            )

            foreach ($field in $requiredFields) {
                if (
                    -not $fields.ContainsKey($field) -or
                    [string]::IsNullOrWhiteSpace($fields[$field])
                ) {
                    throw "Missing required creation event field: $field"
                }
            }

            $processId = ConvertTo-NormalizedProcessId `
                -ProcessId $fields['NewProcessId']

            $parentProcessId = ConvertTo-NormalizedProcessId `
                -ProcessId $fields['ProcessId']

            return [PSCustomObject]@{
                EventId           = 4688
                EventRecordId     = $recordId
                TimeCreatedUtc    = $parsedTime
                ProcessId         = $processId
                ParentProcessId   = $parentProcessId
                ProcessName       = $fields['NewProcessName']
                ParentProcessName = $fields['ParentProcessName']
                CommandLine       = $fields['CommandLine']
                Status            = $null
                EventType         = 'Creation'
            }
        }

        if ($eventId -eq 4689) {
            $requiredFields = @(
                'ProcessId',
                'ProcessName'
            )

            foreach ($field in $requiredFields) {
                if (
                    -not $fields.ContainsKey($field) -or
                    [string]::IsNullOrWhiteSpace($fields[$field])
                ) {
                    throw "Missing required termination event field: $field"
                }
            }

            $processId = ConvertTo-NormalizedProcessId `
                -ProcessId $fields['ProcessId']

            return [PSCustomObject]@{
                EventId           = 4689
                EventRecordId     = $recordId
                TimeCreatedUtc    = $parsedTime
                ProcessId         = $processId
                ParentProcessId   = $null
                ProcessName       = $fields['ProcessName']
                ParentProcessName = $null
                CommandLine       = $null
                Status            = $fields['Status']
                EventType         = 'Termination'
            }
        }

        throw "Unsupported event ID: $eventId"
    }
    catch {
        throw "Failed to parse process lifecycle event: $($_.Exception.Message)"
    }
}


function Invoke-ProcessLifetimeCorrelation {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Events
    )

    $instances = [System.Collections.Generic.List[object]]::new()
    $unmatchedTerminations = [System.Collections.Generic.List[object]]::new()
    $anomalies = [System.Collections.Generic.List[object]]::new()

    $activeProcesses = @{}
    $blockedProcesses = @{}

    # Sort by timestamp, then event record ID.
    $orderedEvents = @(
        $Events | Sort-Object `
            @{ Expression = { $_.TimeCreatedUtc } },
            @{ Expression = { [long]$_.EventRecordId } }
    )

    foreach ($event in $orderedEvents) {

        if ($event.EventType -notin @('Creation', 'Termination')) {
            throw "Unsupported event type: $($event.EventType)"
        }

        $pidKey = [string]$event.ProcessId

        if ($event.EventType -eq 'Creation') {

            $instance = [PSCustomObject]@{
                ProcessId            = $event.ProcessId
                ProcessName          = $event.ProcessName
                ParentProcessId      = $event.ParentProcessId
                CreatedAt            = $event.TimeCreatedUtc
                TerminatedAt         = $null
                Lifetime             = $null
                Status               = 'NoTerminationObserved'
                CreationRecordId     = $event.EventRecordId
                TerminationRecordId  = $null
            }

            $instances.Add($instance)

            # A PID already active or blocked cannot be safely correlated.
            if (
                $activeProcesses.ContainsKey($pidKey) -or
                $blockedProcesses.ContainsKey($pidKey)
            ) {
                if ($activeProcesses.ContainsKey($pidKey)) {
                    $activeProcesses[$pidKey].Status = 'AmbiguousDuplicateCreation'
                    $activeProcesses.Remove($pidKey)
                }

                $instance.Status = 'AmbiguousDuplicateCreation'
                $blockedProcesses[$pidKey] = $true

                $anomalies.Add([PSCustomObject]@{
                    Type      = 'DuplicateCreation'
                    ProcessId = $event.ProcessId
                    Timestamp = $event.TimeCreatedUtc
                })

                continue
            }

            $activeProcesses[$pidKey] = $instance
        }

        elseif ($event.EventType -eq 'Termination') {

            # A previously detected duplicate makes this PID ambiguous.
            if ($blockedProcesses.ContainsKey($pidKey)) {
                $unmatchedTerminations.Add($event)
                $blockedProcesses.Remove($pidKey)
                continue
            }

            if (-not $activeProcesses.ContainsKey($pidKey)) {
                $unmatchedTerminations.Add($event)
                continue
            }

            $instance = $activeProcesses[$pidKey]

            $creationName = [System.IO.Path]::GetFileName(
                $instance.ProcessName
            )

            $terminationName = [System.IO.Path]::GetFileName(
                $event.ProcessName
            )

            $instance.TerminatedAt = $event.TimeCreatedUtc
            $instance.TerminationRecordId = $event.EventRecordId

            if ($event.TimeCreatedUtc -lt $instance.CreatedAt) {
                $instance.Status = 'InvalidEventOrder'
                $anomalies.Add([PSCustomObject]@{
                    Type      = 'InvalidEventOrder'
                    ProcessId = $event.ProcessId
                })
            }
            else {
                $instance.Lifetime = (
                    $event.TimeCreatedUtc - $instance.CreatedAt
                )

                if ($creationName -ine $terminationName) {
                    $instance.Status = 'ProcessNameMismatch'

                    $anomalies.Add([PSCustomObject]@{
                        Type          = 'ProcessNameMismatch'
                        ProcessId     = $event.ProcessId
                        CreatedAs     = $instance.ProcessName
                        TerminatedAs  = $event.ProcessName
                    })
                }
                else {
                    $instance.Status = 'Matched'
                }
            }

            $activeProcesses.Remove($pidKey)
        }
    }

    return [PSCustomObject]@{
        ProcessInstances      = @($instances.ToArray())
        UnmatchedTerminations = @($unmatchedTerminations.ToArray())
        Anomalies              = @($anomalies.ToArray())
    }
}
