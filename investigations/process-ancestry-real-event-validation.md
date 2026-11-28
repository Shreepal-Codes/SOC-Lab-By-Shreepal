# Process Ancestry Reconstruction — Real Windows Event Validation

## 1. Objective

Validate the process ancestry reconstruction engine against actual Windows Security audit events.

The objective was to determine whether the engine could correctly identify a parent-child process relationship using Windows Security Event IDs 4688 (process creation) and 4689 (process termination).

A controlled process execution was performed to generate real process activity:

- Parent process: Windows PowerShell
- Child process: PING.EXE

The resulting Security events were retrieved and passed through the existing process lifecycle analysis and ancestry reconstruction functions.

## 2. Test Environment

| Attribute | Value |
|---|---|
| Operating System | Windows 11 |
| Event Log | Windows Security |
| Event IDs | 4688, 4689 |
| Parent Process | powershell.exe |
| Parent PID | 3100 |
| Child Process | PING.EXE |
| Child PID | 12016 |
| Validation Type | Real Windows event validation |

## 3. Controlled Process Execution

A PING process was launched from the active PowerShell session.

The following PowerShell commands were used:

```powershell
$experimentStart = Get-Date

$testProcess = Start-Process `
    -FilePath "$env:WINDIR\System32\PING.EXE" `
    -ArgumentList @('-n', '11', '127.0.0.1') `
    -PassThru

$childPid = [uint64]$testProcess.Id
$parentPid = [uint64]$PID

Write-Host "Parent PowerShell PID: $parentPid"
Write-Host "Child PING PID: $childPid"

$testProcess.WaitForExit()
```

Observed process identifiers:

- Parent PowerShell PID: `3100`
- Child PING PID: `12016`

The child process was allowed to finish before its corresponding event records were retrieved.

## 4. Windows Security Event Evidence

Four actual Security event records were retrieved using their Event Record IDs.

### 4.1 Parent process creation

| Field | Value |
|---|---|
| Event ID | 4688 |
| Event Record ID | 2454960 |
| Time (UTC) | 2026-11-28 11:36:09 |
| New Process ID | 0xC1C (3100) |
| New Process Name | powershell.exe |
| Creator Process ID | 0x24E8 (9448) |
| Creator Process Name | explorer.exe |

This event establishes the creation of the PowerShell process.

### 4.2 Child process creation

| Field | Value |
|---|---|
| Event ID | 4688 |
| Event Record ID | 2456159 |
| Time (UTC) | 2026-11-28 11:43:47 |
| New Process ID | 0x2EF0 (12016) |
| New Process Name | PING.EXE |
| Creator Process ID | 0xC1C (3100) |
| Creator Process Name | powershell.exe |

This event records PowerShell as the creator process of PING.EXE.

### 4.3 Child process termination

| Field | Value |
|---|---|
| Event ID | 4689 |
| Event Record ID | 2456161 |
| Time (UTC) | 2026-11-28 11:43:58 |
| Process ID | 0x2EF0 (12016) |
| Process Name | PING.EXE |

This event records the termination of the child process.

### 4.4 Parent process termination

| Field | Value |
|---|---|
| Event ID | 4689 |
| Event Record ID | 2456253 |
| Time (UTC) | 2026-11-28 11:50:52 |
| Process ID | 0xC1C (3100) |
| Process Name | powershell.exe |
| Exit Status | 0xC000013A |

This event records the termination of the parent PowerShell process.

## 5. Process Ancestry Reconstruction

The four retrieved Windows Security events were converted into normalized lifecycle events using:

`ConvertFrom-ProcessLifecycleEvent`

The resulting events were supplied to:

`Invoke-ProcessAncestryReconstruction`

The reconstruction engine correlated process creation and termination records, matched process instances by PID and lifetime, and evaluated the parent process candidate at the child's creation time.

### 5.1 Reconstructed relationship

| Field | Result |
|---|---|
| Child Process ID | 12016 |
| Child Process Name | PING.EXE |
| Parent Process ID | 3100 |
| Parent Process Name | powershell.exe |
| Parent Creation Record ID | 2454960 |
| Child Creation Record ID | 2456159 |
| Relationship Status | Confirmed |
| Reason | OneParentInstanceFitsCreationTime |
| Parent Name Match | True |

### 5.2 Process lifetime correlation

**Parent — PowerShell**

| Field | Result |
|---|---|
| Process ID | 3100 |
| Creation Record ID | 2454960 |
| Termination Record ID | 2456253 |
| Created At (UTC) | 2026-11-28 11:36:09 |
| Terminated At (UTC) | 2026-11-28 11:50:52 |
| Calculated Lifetime | 00:14:42.9799872 |
| Status | Matched |

**Child — PING.EXE**

| Field | Result |
|---|---|
| Process ID | 12016 |
| Creation Record ID | 2456159 |
| Termination Record ID | 2456161 |
| Created At (UTC) | 2026-11-28 11:43:47 |
| Terminated At (UTC) | 2026-11-28 11:43:58 |
| Calculated Lifetime | 00:00:10.1862498 |
| Status | Matched |

Both process instances had successfully matched creation and termination events.

## 6. Validation Outcome

**Result: Successful**

The ancestry reconstruction engine correctly identified PowerShell as the parent of PING.EXE using actual Windows Security event data.

The following conditions were verified:

- Both process creation events were successfully parsed.
- Both process termination events were successfully parsed.
- Parent and child process instances were correlated.
- The parent process existed at the child's creation time.
- The parent PID matched the creator PID recorded in the child's creation event.
- The parent process name matched the recorded creator process name.
- Both process lifetimes were successfully matched.
- The reconstructed relationship was classified as `Confirmed`.

The engine returned:

```text
RelationshipStatus : Confirmed
Reason             : OneParentInstanceFitsCreationTime
ParentNameMatch    : True
```

## 7. Limitations and Interpretation

A `Confirmed` relationship represents a unique parent process instance satisfying the engine's available PID and timestamp correlation criteria.

It should not be interpreted as cryptographic proof of process ancestry.

The reliability of reconstruction depends on the availability, integrity, and completeness of Windows Security audit events.

Potential limitations include:

- Missing or overwritten event records.
- Incomplete process creation or termination auditing.
- PID reuse.
- Multiple candidate parent instances.
- Missing parent process history.
- Inconsistent or incomplete event fields.

The engine accounts for several of these situations through its relationship classifications and anomaly handling, but incomplete event evidence can still prevent reliable reconstruction.

## 8. Conclusion

This validation demonstrates that the process ancestry reconstruction engine works with real Windows Security audit data, beyond its synthetic test scenarios.

It successfully reconstructed a PowerShell-to-PING process relationship and correlated the lifetimes of both processes.

This provides practical evidence that the project can support process investigation workflows relevant to endpoint monitoring and SOC analysis.

**Validation status:** Successful
**Evidence source:** Windows Security Event IDs 4688 and 4689
**Parent-child relationship:** PowerShell (3100) → PING.EXE (12016)