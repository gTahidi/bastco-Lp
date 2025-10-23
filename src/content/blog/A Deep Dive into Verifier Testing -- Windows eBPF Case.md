---
title: "A Deep Dive into Verifier Testing -- Windows eBPF Case"
description: "Verifier Testing Windows eBPF"
pubDate: 2025-10-23
author: "addcontent"
tags:
  - ebpf
category: "Cybersecurity"
---

# A Deep Dive into Verifier Testing -- Windows eBPF Case

**Author:** addcontent  
**Date:** October 2025  


## Introduction

Over the past several weeks, I conducted a comprehensive security assessment of Windows eBPF for Windows (version 0.21.1), with a specific focus on the verifier component. This post documents my methodology, findings, and observations from testing 30 different attack patterns designed to identify potential vulnerabilities in the eBPF verifier.

The motivation for this research came from the rich history of eBPF verifier vulnerabilities in Linux. CVEs like CVE-2020-8835, CVE-2021-3490, and CVE-2022-23222 have shown that even well-designed verifiers can have subtle flaws that lead to exploitable conditions. Given that Windows eBPF is a relatively newer implementation, I wanted to understand whether it shared similar vulnerabilities or if Microsoft's implementation had learned from these historical issues.

Spoiler alert: The Windows eBPF verifier passed all tests. While this might seem like an anticlimactic conclusion, the journey and methodology are worth documenting for the security research community.

## Background: The Role of eBPF Verifiers

Before diving into the technical details, it's important to understand what an eBPF verifier does and why it matters from a security perspective.

eBPF (extended Berkeley Packet Filter) allows users to run sandboxed programs in the kernel without changing kernel source code or loading kernel modules. This is incredibly powerful for networking, observability, and security applications. However, running user-supplied code in kernel space is inherently risky.

The verifier's job is to analyze eBPF programs before they execute and ensure they:
- Cannot access memory outside their allowed bounds
- Cannot cause kernel crashes or undefined behavior
- Terminate in a finite amount of time
- Only perform operations they're authorized to do

A flaw in the verifier means an attacker could potentially bypass these checks and gain arbitrary kernel code execution, leading to complete system compromise.

## Historical Context: Linux eBPF Vulnerabilities

To understand what to look for in Windows eBPF, I first studied the history of Linux eBPF vulnerabilities. Here are some notable examples that informed my testing strategy:

### CVE-2020-8835: ALU32 Bounds Bypass

This vulnerability, discovered by Manfred Paul, involved incorrect tracking of 32-bit ALU operations. The Linux verifier failed to properly track bounds when programs used 32-bit arithmetic operations that could overflow. An attacker could craft a program that:

1. Created a 32-bit value near the maximum (0x7FFFFFFF)
2. Added a small value causing overflow
3. Used the result as an array index
4. The verifier incorrectly tracked bounds, allowing out-of-bounds access

This pattern became a template for one of my primary test cases.

### CVE-2021-3490: ALU32 Variant

A variant of the previous vulnerability showed that fixing one instance of ALU32 issues didn't address all similar cases. This highlighted the importance of systematic testing across different operation types.

### CVE-2022-23222: Type Confusion

This vulnerability involved confusion between different pointer types in the verifier. The verifier could be tricked into treating one type of pointer as another, leading to unauthorized memory access.

These historical vulnerabilities share common themes:
- Arithmetic overflow leading to bounds check bypass
- Type system weaknesses
- Incorrect state tracking across execution paths

My testing strategy focused heavily on these patterns.

## Reconnaissance Phase

### Understanding the Architecture

Windows eBPF consists of several components:

**User-mode components:**
- ebpfapi.dll: Provides the API for loading and managing eBPF programs
- ebpfnetsh.dll: Extends netsh.exe with eBPF-specific commands
- netsh.exe: Command-line interface for eBPF operations

**Kernel-mode components:**
- ebpfcore.sys: The core driver containing the verifier, JIT compiler, and runtime

The typical workflow is:
1. User compiles eBPF C code to bytecode using clang
2. User loads the program via netsh or API
3. ebpfapi.dll reads the ELF file and sends it to the kernel
4. ebpfcore.sys verifier analyzes the program
5. If verification passes, the JIT compiler converts it to native code
6. The program is attached to hook points and begins executing

### DLL Analysis

I started by examining the user-mode DLLs to understand the API surface. Using standard tools, I identified key functions in ebpfapi.dll:

```
ebpf_api_create_program
ebpf_api_load_program
ebpf_api_verify_program
ebpf_api_get_program_info
```

The important discovery here was that all security-critical decisions happen in the kernel driver. The user-mode DLLs are essentially wrappers that facilitate communication with the kernel. This meant my focus needed to be entirely on how ebpfcore.sys verifies programs.

### Initial Testing

My first test was simple: can I load an obviously invalid program?

```c
SEC("bind")
int test_obvious_oob(struct bpf_sock_addr *ctx)
{
    uint8_t *base = (uint8_t *)ctx;
    return base[100];  // Structure is only 56 bytes
}
```

Result: Rejected with error "Upper bound must be at most 56"

This confirmed that basic bounds checking was working. The verifier knew the size of the context structure and caught the obvious out-of-bounds access.

## Test Development Methodology

Based on my study of Linux CVEs and initial reconnaissance, I developed a systematic testing approach with four categories:

### Category 1: Baseline Tests

Purpose: Establish what the verifier should accept and reject

**Negative baseline (test_invalid.c):** Programs with obvious bugs that must be rejected
**Positive baseline (test_windows.c):** Harmless code that should be accepted

The positive baseline was interesting. I created a program with arithmetic overflow but no memory access:

```c
SEC("bind")
int test_overflow_bind(struct bpf_sock_addr *ctx)
{
    uint64_t a = 0xFFFFFFFE;
    uint64_t b = 0x00000002;
    uint64_t result = a + b;  // Overflow occurs here
    
    if (result < 100) {  // Dead code, never executes
        return 0;
    }
    return 1;
}
```

This loaded successfully. At first, I wondered if this indicated a vulnerability, but further analysis revealed it was the correct behavior. The overflow occurs in pure arithmetic with no memory safety implications. The dead code is unreachable. The verifier allowing this shows it distinguishes between harmless arithmetic and dangerous operations.

### Category 2: Direct Exploitation Attempts

Based on CVE-2020-8835, I created test_alu_bounds.c with seven test functions:

**Test 1: ALU32 Addition Overflow to OOB Access**
```c
SEC("bind")
int test_alu32_oob(struct bpf_sock_addr *ctx)
{
    uint8_t *base = (uint8_t *)ctx;
    uint32_t offset32 = 0x7FFFFFFF;
    offset32 += 1;  // Overflow to 0x80000000
    uint32_t index = offset32 & 0xFF;
    
    if (index < 56) {
        uint8_t value = base[index];
        return value;
    }
    return 1;
}
```

The theory: Create an overflow in 32-bit arithmetic, then use the result to access memory. If the verifier tracks bounds incorrectly like the vulnerable Linux version, this would succeed.

Result: Rejected with "Invalid type (r0.type == number)"

This error message was revealing. The verifier wasn't saying "bounds error" or "out of range." It was saying the register contained a number (scalar) rather than a valid pointer offset. This indicated a type system enforcement.

**Test 2: ALU64 vs ALU32 Confusion**
```c
SEC("bind")
int test_alu_confusion(struct bpf_sock_addr *ctx)
{
    uint8_t *base = (uint8_t *)ctx;
    uint64_t offset64 = 0xFFFFFFFF;
    offset64 += 1;  // Now 0x100000000
    uint32_t offset32 = (uint32_t)offset64;  // Truncates to 0
    
    if (offset32 < 56) {
        uint8_t value = base[offset32];
        return value;
    }
    return 1;
}
```

Theory: Perhaps the verifier gets confused when mixing 64-bit and 32-bit operations.

Result: Rejected with same type error.

I created five more variations testing:
- User-controlled overflow values
- Bounds invalidation after overflow
- Signed/unsigned confusion
- Conditional overflows
- Arithmetic chains

All were rejected with type errors.

### Category 3: Evasion Techniques

After direct approaches failed, I developed ten evasion techniques in test_evasion.c designed to obscure the attack pattern:

**Context Round-trip:**
The idea was to store an overflowed value in the context structure, then retrieve it, hoping the verifier would lose track of the taint.

**Branch Confusion:**
Use complex branching to make the verifier's path analysis fail or lose precision when merging states.

**Pointer Arithmetic vs Array Indexing:**
Perhaps using pointer arithmetic (`ptr = base + offset; val = *ptr`) would have different checks than array indexing (`val = base[offset]`).

**Nested Conditions:**
Deep nesting might exhaust the verifier's analysis depth or cause it to make conservative but incorrect assumptions.

**Loop-based Obfuscation:**
Bounded loops that transform indices in ways the verifier might not track precisely.

All ten techniques failed with the same type error.

### Category 4: Advanced Evasion

I created ten more sophisticated techniques in test_advanced_evasion.c:

**Overflow in Comparison:**
Use overflow in a comparison that influences control flow, which then affects the index used for memory access.

**XOR Obfuscation:**
Multiple XOR operations to obscure the data flow.

**Multiplication Overflow:**
Different arithmetic operation, perhaps tracked differently than addition.

**Shift Operations:**
Bit shifts are mathematically equivalent to multiplication/division but might be handled separately in the verifier.

**Modulo Operations:**
The verifier should know that `x % 64` is in range [0, 63], but perhaps it doesn't track modulo correctly.

Again, all failed with type errors.

## The Pattern: Type System Enforcement

After 29 failed tests, a clear pattern emerged. The Windows eBPF verifier implements a strong type system for registers. Each register is tagged with a type:

- PTR_TO_CTX: Pointer to the context structure
- PTR_TO_PACKET: Pointer to packet data
- PTR_TO_MAP_VALUE: Pointer to a map value
- SCALAR_VALUE: A number resulting from arithmetic

The critical rule: You can only dereference registers that are pointer types. Scalar values, no matter how they're created or transformed, cannot be used as pointers.

When my test programs tried to do:
```c
uint32_t index = /* some calculation */;
uint8_t value = base[index];
```

The verifier saw:
- base: PTR_TO_CTX (valid)
- index: SCALAR_VALUE (invalid for dereferencing)

The operation was rejected not because the bounds were wrong, but because the type system prevented using arbitrary scalars as memory offsets.

This is fundamentally different from bounds checking alone. It's a more conservative approach that prevents an entire class of attacks.

## Why The Attacks Failed: Technical Analysis

Let me break down why each attack category failed:

### Direct Exploitation

These failed because they all followed the same pattern:
1. Perform arithmetic to create a value
2. Try to use that value for memory access

No matter what arithmetic operations you perform, the result is always typed as SCALAR_VALUE. The verifier never allows converting a scalar to a pointer offset without validation.

### Evasion Through Indirection

I tried storing values in the context structure and retrieving them:
```c
uint32_t overflow = calculate_overflow();
ctx->user_port = overflow;  // Store
uint32_t retrieved = ctx->user_port;  // Load
uint8_t data = base[retrieved];  // Use
```

The retrieved value is still typed as SCALAR_VALUE because it's loaded from memory. The type system doesn't care where the value came from; it only cares what type it is.

### Evasion Through Obfuscation

Complex control flow, multiple operations, XOR, shifts, modulo - none of this matters. The type system tracks through all of these operations. If you start with a scalar and perform scalar operations, you end with a scalar.

### The Exception: Why test_windows.c Loaded

One program did load successfully - the one with arithmetic overflow in dead code. This might seem contradictory, but it's actually correct behavior:

```c
uint64_t result = a + b;  // Overflow happens
if (result < 100) {       // Comparison only
    return 0;             // Return a constant
}
```

There's no memory access using the overflowed value. The verifier allows arithmetic operations, even ones that overflow, as long as they don't lead to unsafe memory access. This is the right design: be permissive for safe operations, strict for dangerous ones.

## Verifier Implementation Insights

Based on the error messages and behavior, I can infer some details about the Windows eBPF verifier implementation:

### Register State Tracking

The verifier maintains detailed state for each register including:
- Type (pointer vs scalar and pointer subtypes)
- For scalars: potential range of values
- For pointers: base pointer and valid offset range

### Path Sensitivity

The verifier analyzes all possible execution paths through the program. At branch merge points, it conservatively merges the state from both paths. If a register is a scalar on one path and a scalar on another, the merged state is still scalar with the union of possible values.

### Conservative Analysis

When in doubt, the verifier rejects. This is evident in how it handles complex control flow - rather than trying to prove safety, it requires proof of safety. If it can't determine that an operation is safe, it rejects the program.

## Comparison: Windows vs Linux eBPF

The Windows implementation appears to have learned from Linux's CVE history:

**Linux CVE-2020-8835 Pattern:**
- Verifier tracked bounds but lost precision with 32-bit overflow
- Allowed using the result for memory access
- Exploitable

**Windows Behavior:**
- Type system prevents using arbitrary scalars for memory access
- Doesn't matter if bounds tracking has imprecision
- Not exploitable via this vector

The type system acts as a defense-in-depth mechanism. Even if bounds tracking were imperfect (I found no evidence of this), the type system would prevent exploitation.

## Testing Limitations and Future Work

My testing had several limitations:

**Scope:**
I focused primarily on arithmetic overflow and type confusion. I didn't extensively test:
- Map operations and reference counting
- Helper function return values
- Race conditions in program loading
- JIT compiler bugs separate from verifier issues
- Windows-specific helper functions

**Coverage:**
While 30 test cases based on known patterns is substantial, it's not exhaustive. Novel attack vectors might exist.

**Dynamic Analysis:**
My testing was primarily static - trying to load programs and observing rejection. I didn't extensively analyze runtime behavior of programs that did load.

**Version Specific:**
Testing was done on version 0.21.1. Future versions might introduce new features or bugs.

Future research could explore:
- Map-in-map structures and complex map operations
- Concurrent program loading and TOCTOU vulnerabilities
- Speculative execution side channels
- JIT compiler code generation bugs
- Windows-specific attack surfaces

## Responsible Disclosure Considerations

I did not report any findings to Microsoft Security Response Center (MSRC) because:

1. **No vulnerability found:** All exploitation attempts were correctly blocked.

2. **test_windows.c is not a bug:** The program that loaded contains harmless arithmetic. Reporting this would be a false positive.

3. **No security impact:** None of the tested patterns resulted in memory safety violations or security boundary bypasses.

## Technical Observations

The Windows eBPF verifier's type system prevented an entire class of attacks that have historically affected Linux eBPF. The strict typing approach, where scalar values cannot be used as pointer offsets, proved more robust than purely bounds-based verification.

The defense-in-depth architecture means that even if bounds tracking had imprecision, the type system would prevent exploitation. This layered approach significantly raises the bar for attackers.

The verifier's conservative analysis - rejecting programs when safety cannot be proven rather than trying to prove unsafety - is appropriate for a kernel security component. This design philosophy accepts some false positives (rejecting safe programs) to eliminate false negatives (accepting unsafe programs).

## Conclusion

After testing 30 attack patterns designed to bypass the Windows eBPF verifier, I found no exploitable vulnerabilities. The verifier's type system successfully prevented all exploitation attempts based on arithmetic overflow and type confusion.

This doesn't mean Windows eBPF is perfect or that vulnerabilities don't exist. It means that for the specific attack vectors I tested - informed by historical Linux eBPF CVEs - the Windows implementation is robust.

The key security property is the strict type system that prevents using arbitrary scalar values as memory access offsets. This design choice creates a strong security boundary that proved resistant to various evasion techniques.

The systematic testing methodology based on historical CVE patterns proved effective for evaluating the verifier. This serves as independent validation that the tested attack vectors are well-defended against in the current implementation.

## Methodology Transparency

In the interest of reproducibility, all test code, compilation commands, and detailed results are available in my research repository. The complete technical documentation includes:

- Source code for all 30 test programs
- Compilation procedures
- Exact error messages from the verifier
- Analysis of verifier behavior
- Comparisons to Linux eBPF vulnerabilities

## Acknowledgments

This research was conducted independently with no affiliation to Microsoft. The Windows eBPF for Windows project is open source, and I appreciate the availability of the code and documentation that made this research possible.

The broader eBPF security research community, particularly those who discovered and documented Linux eBPF vulnerabilities, provided the foundation that made systematic testing possible.

---

**Author's Note:** This research was conducted in October 2025 on Windows eBPF for Windows version 0.21.1. Security landscapes evolve, and future versions may introduce new features or behaviors. This analysis is specific to the tested version and attack patterns.


**Overall Assessment:** Verifier demonstrates robust security against tested attack vectors