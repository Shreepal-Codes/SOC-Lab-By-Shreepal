
function Invoke-ProcessAncestryReconstruction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Events
    )

    if (-not (Get-Command Invoke-ProcessLifetimeCorrelation -ErrorAction SilentlyContinue)) {
        throw "Load process-ancestry-analysis.ps1 before running ancestry reconstruction."
    }

    $creationEvents = @(
        $Events | Where-Object { $_.EventType -eq 'Creation' }
    )

    $lifecycleResult = Invoke-ProcessLifetimeCorrelation -Events $Events

    $processInstances = @($lifecycleResult.ProcessInstances)

    $relationships = [System.Collections.Generic.List[object]]::new()
    $anomalies = [System.Collections.Generic.List[object]]::new()

    foreach ($child in $processInstances) {

        # Find the original creation event for this process instance.
        $creationEvent = $null

        if (-not [string]::IsNullOrWhiteSpace([string]$child.CreationRecordId)) {
            $creationEvent = $creationEvents |
                Where-Object {
                    [string]$_.EventRecordId -eq [string]$child.CreationRecordId
                } |
                Select-Object -First 1
        }

        # Fall back to PID and creation timestamp if no record ID exists.
        if ($null -eq $creationEvent) {
            $creationEvent = $creationEvents |
                Where-Object {
                    $_.ProcessId -eq $child.ProcessId -and
                    $_.TimeCreatedUtc -eq $child.CreatedAt
                } |
                Select-Object -First 1
        }

        if ($null -eq $creationEvent) {
            $relationships.Add([PSCustomObject]@{
                ChildProcessId   = $child.ProcessId
                ChildProcessName = $child.ProcessName
                ParentProcessId  = $child.ParentProcessId
                ParentProcessName = $null
                ParentCreationRecordId = $null
                ChildCreationRecordId = $child.CreationRecordId
                RelationshipStatus = 'Unresolved'
                Reason = 'CreationEventNotAvailable'
                ParentNameMatch = $null
            })

            continue
        }

        $parentPid = $child.ParentProcessId
        $observedParentName = $creationEvent.ParentProcessName

        # A process cannot be its own parent.
        if ($parentPid -eq $child.ProcessId) {

            $relationships.Add([PSCustomObject]@{
                ChildProcessId   = $child.ProcessId
                ChildProcessName = $child.ProcessName
                ParentProcessId  = $parentPid
                ParentProcessName = $observedParentName
                ParentCreationRecordId = $null
                ChildCreationRecordId = $child.CreationRecordId
                RelationshipStatus = 'SelfReference'
                Reason = 'ChildAndParentProcessIdsAreIdentical'
                ParentNameMatch = $null
            })

            $anomalies.Add([PSCustomObject]@{
                Type = 'SelfReferencingProcess'
                ProcessId = $child.ProcessId
                CreationRecordId = $child.CreationRecordId
            })

            continue
        }

        # Find every instance of the reported parent PID.
        $parentPidInstances = @(
            $processInstances | Where-Object {
                $_.ProcessId -eq $parentPid
            }
        )

        # A parent must have existed when the child was created.
        $validParents = @(
            $parentPidInstances | Where-Object {
                $_.CreatedAt -le $child.CreatedAt -and
                (
                    $null -eq $_.TerminatedAt -or
                    $_.TerminatedAt -ge $child.CreatedAt
                )
            }
        )

        if ($validParents.Count -eq 0) {

            $reason = if ($parentPidInstances.Count -eq 0) {
                'ParentProcessNotObserved'
            }
            else {
                'NoParentInstanceActiveAtChildCreation'
            }

            $relationships.Add([PSCustomObject]@{
                ChildProcessId   = $child.ProcessId
                ChildProcessName = $child.ProcessName
                ParentProcessId  = $parentPid
                ParentProcessName = $observedParentName
                ParentCreationRecordId = $null
                ChildCreationRecordId = $child.CreationRecordId
                RelationshipStatus = 'Unresolved'
                Reason = $reason
                ParentNameMatch = $null
            })

            continue
        }

        # More than one valid parent instance means PID correlation
        # cannot safely establish a unique ancestry relationship.
        if ($validParents.Count -gt 1) {

            $relationships.Add([PSCustomObject]@{
                ChildProcessId   = $child.ProcessId
                ChildProcessName = $child.ProcessName
                ParentProcessId  = $parentPid
                ParentProcessName = $observedParentName
                ParentCreationRecordId = $null
                ChildCreationRecordId = $child.CreationRecordId
                RelationshipStatus = 'Ambiguous'
                Reason = 'MultipleParentInstancesFitCreationTime'
                ParentNameMatch = $null
            })

            $anomalies.Add([PSCustomObject]@{
                Type = 'AmbiguousParentRelationship'
                ChildProcessId = $child.ProcessId
                ParentProcessId = $parentPid
                CandidateCount = $validParents.Count
            })

            continue
        }

        # Exactly one parent instance fits the available timeline.
        $parent = $validParents[0]

        $parentNameMatch = $null

        if (-not [string]::IsNullOrWhiteSpace([string]$observedParentName)) {

            $observedName = [System.IO.Path]::GetFileName(
                [string]$observedParentName
            )

            $actualName = [System.IO.Path]::GetFileName(
                [string]$parent.ProcessName
            )

            $parentNameMatch = ($observedName -ieq $actualName)

            if (-not $parentNameMatch) {
                $anomalies.Add([PSCustomObject]@{
                    Type = 'ParentProcessNameMismatch'
                    ChildProcessId = $child.ProcessId
                    ParentProcessId = $parentPid
                    ObservedParentName = $observedParentName
                    MatchedParentName = $parent.ProcessName
                })
            }
        }

        $relationships.Add([PSCustomObject]@{
            ChildProcessId   = $child.ProcessId
            ChildProcessName = $child.ProcessName
            ParentProcessId  = $parent.ProcessId
            ParentProcessName = $parent.ProcessName
            ParentCreationRecordId = $parent.CreationRecordId
            ChildCreationRecordId = $child.CreationRecordId
            RelationshipStatus = 'Confirmed'
            Reason = 'OneParentInstanceFitsCreationTime'
            ParentNameMatch = $parentNameMatch
        })
    }

    $relationshipArray = @($relationships.ToArray())

    return [PSCustomObject]@{
        ProcessInstances = $processInstances
        Relationships = $relationshipArray

        ConfirmedRelationships = @(
            $relationshipArray | Where-Object {
                $_.RelationshipStatus -eq 'Confirmed'
            }
        )

        AmbiguousRelationships = @(
            $relationshipArray | Where-Object {
                $_.RelationshipStatus -eq 'Ambiguous'
            }
        )

        UnresolvedRelationships = @(
            $relationshipArray | Where-Object {
                $_.RelationshipStatus -eq 'Unresolved'
            }
        )

        Anomalies = @(
            @($lifecycleResult.Anomalies) + @($anomalies.ToArray())
        )
    }
}
