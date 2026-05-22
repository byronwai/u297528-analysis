#!/usr/bin/env python3
"""
API Hash Resolution for u297528.dat
Generates hash resolution database and attempts to crack unresolved hashes
"""

import json, os, itertools

OUT_DIR = "/home/kali/Downloads/sandbox/findings"

def compute_hash(name, lowercase=False):
    """Custom API hashing: hash = 0xe7A1; hash = hash * 0x21 + char"""
    hash_val = 0xe7a1
    for c in name:
        if lowercase:
            c = c.lower()
        hash_val = (hash_val * 0x21 + ord(c)) & 0xFFFFFFFF
    return hash_val

def compute_hash_unicode(name):
    """DLL name hashing with Unicode WCHAR (uppercase converted)"""
    hash_val = 0xe7a1
    for c in name:
        c = c.upper()
        hash_val = (hash_val * 0x21 + ord(c)) & 0xFFFFFFFF
    return hash_val

def brute_force_char_hash(target_hash, max_len=20):
    """Brute force short names to find hash matches"""
    charset = list(range(0x41, 0x5B))  # A-Z uppercase
    charset.extend(range(0x61, 0x7B))  # a-z lowercase
    charset.extend(range(0x30, 0x3A))  # 0-9
    charset.extend([0x2E, 0x5F, 0x2D, 0x20])  # ., _, -, space
    
    # Try 1-4 character names
    for length in range(1, min(max_len, 5)):
        for combo in itertools.product(charset, repeat=length):
            name = ''.join(chr(c) for c in combo)
            h = compute_hash(name, lowercase=False)
            if h == target_hash:
                return name
            h2 = compute_hash(name, lowercase=True)
            if h2 == target_hash:
                return name + " (lowercase)"
    return None

def main():
    results = {}
    
    # === Known Hash Values ===
    func_hashes = {
        0x695b8977: {"resolved": "NtCreateFile", "storage": "[0x180c51530]", "type": "syscall_number"},
        0x4d799fce: {"resolved": "NtWriteFile", "storage": "[0x180c51534]", "type": "syscall_number"},
        0x844c5e59: {"resolved": "NtClose", "storage": "[0x180c51538]", "type": "syscall_number"},
        0x82a35258: {"resolved": None, "storage": "[0x180c51540]", "type": "syscall_number"},
        0x427392e6: {"resolved": None, "storage": "[0x180c51544]", "type": "syscall_number"},
        0xeb7a1a75: {"resolved": None, "storage": "[0x180c5153c]", "type": "syscall_number"},
        0x79468157: {"resolved": None, "storage": "[0x180c51548]", "type": "function_pointer"},
        0x77a3ed30: {"resolved": None, "storage": "[0x180c51550]", "type": "function_pointer"},
        0x5435a0bf: {"resolved": None, "storage": "[0x180c51558]", "type": "function_pointer"},
        0xceb013a2: {"resolved": None, "storage": "[0x180c51560]", "type": "function_pointer"},
    }
    
    dll_hashes = {
        0x46ca3d07: {"resolved": None, "role": "first_module"},
        0x40583309: {"resolved": None, "role": "second_module (likely NTDLL)"},
    }
    
    # === Generate Hash Database ===
    hash_db = {}
    
    # Generate DLL hashes
    dll_names = [
        "ntdll.dll", "kernel32.dll", "kernelbase.dll", "user32.dll",
        "advapi32.dll", "ws2_32.dll", "wininet.dll", "winhttp.dll",
        "msvcrt.dll", "ucrtbase.dll", "vcruntime140.dll", "crypt32.dll",
        "shell32.dll", "ole32.dll", "oleaut32.dll", "gdi32.dll",
        "psapi.dll", "shlwapi.dll", "secur32.dll", "iphlpapi.dll",
        "dnsapi.dll", "mswsock.dll", "dbghelp.dll", "bcrypt.dll",
        "bcryptprimitives.dll", "msvcp140.dll", "vcruntime140_1.dll",
        "idll.dll", "mpr.dll", "netapi32.dll", "wldap32.dll",
        "credui.dll", "authz.dll", "sspicli.dll", "profapi.dll",
        "powrprof.dll", "cfgmgr32.dll", "devobj.dll", "setupapi.dll",
        "wintrust.dll", "msasn1.dll", "imagehlp.dll", "version.dll",
        "mscoree.dll", "urlmon.dll", "wtsapi32.dll", "userenv.dll",
        "apphelp.dll", "sfc.dll", "sfc_os.dll", "imm32.dll",
        "comdlg32.dll", "dwmapi.dll", "uxtheme.dll", "sxs.dll",
        "msi.dll", "cabinet.dll", "mspatcha.dll", "dpapi.dll",
        "cryptnet.dll", "cryptui.dll", "propsys.dll", "xmllite.dll",
        "wevtapi.dll", "tdh.dll", "wer.dll", "faultrep.dll",
        "rasapi32.dll", "mprapi.dll", "rtutils.dll",
    ]
    
    for dll in dll_names:
        h_upper = compute_hash_unicode(dll)  # Unicode uppercase
        h_lower = compute_hash(dll, lowercase=True)  # lowercase
        hash_db[h_upper] = f"DLL(Upper): {dll}"
        hash_db[h_lower] = f"DLL(Lower): {dll}"
    
    # Generate ntdll function hashes
    ntdll_funcs = [
        "NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtFreeVirtualMemory",
        "NtWriteVirtualMemory", "NtReadVirtualMemory", "NtQueryVirtualMemory",
        "NtMapViewOfSection", "NtUnmapViewOfSection", "NtCreateSection",
        "NtOpenSection", "NtExtendSection",
        "NtCreateThreadEx", "NtOpenThread", "NtOpenProcess",
        "NtSuspendThread", "NtResumeThread", "NtTerminateThread",
        "NtTerminateProcess", "NtGetContextThread", "NtSetContextThread",
        "NtSetInformationThread", "NtSetInformationProcess",
        "NtQueryInformationThread", "NtQueryInformationProcess",
        "NtCreateProcess", "NtCreateProcessEx", "NtCreateUserProcess",
        "NtCreateFile", "NtOpenFile", "NtReadFile", "NtWriteFile",
        "NtQueryInformationFile", "NtSetInformationFile",
        "NtDeleteFile", "NtClose",
        "NtCreateEvent", "NtOpenEvent", "NtSetEvent", "NtResetEvent",
        "NtWaitForSingleObject", "NtWaitForMultipleObjects",
        "NtCreateMutant", "NtOpenMutant", "NtReleaseMutant",
        "NtCreateSemaphore", "NtOpenSemaphore", "NtReleaseSemaphore",
        "NtDelayExecution", "NtQueryPerformanceCounter",
        "NtOpenProcessToken", "NtOpenProcessTokenEx",
        "NtOpenThreadToken", "NtOpenThreadTokenEx",
        "NtAdjustPrivilegesToken", "NtDuplicateToken",
        "NtImpersonateThread", "NtCreateToken",
        "NtAccessCheck", "NtAccessCheckByType",
        "NtCreateKey", "NtOpenKey", "NtSetValueKey",
        "NtDeleteValueKey", "NtDeleteKey", "NtEnumerateKey",
        "NtQueryKey", "NtQueryValueKey",
        "NtDeviceIoControlFile", "NtFsControlFile",
        "NtFlushInstructionCache", "NtCancelIoFile",
        "NtQuerySystemInformation", "NtQuerySystemTime",
        "NtLoadDriver", "NtUnloadDriver",
        "NtCreateMailslotFile", "NtCreateNamedPipeFile",
        "NtCreatePort", "NtCreateWaitablePort",
        "NtConnectPort", "NtListenPort",
        "NtOpenSymbolicLinkObject", "NtCreateSymbolicLinkObject",
        "NtOpenDirectoryObject", "NtCreateDirectoryObject",
        "NtCreateIoCompletion", "NtOpenIoCompletion",
        "NtSetIoCompletion", "NtRemoveIoCompletion",
        "NtCreateJobObject", "NtOpenJobObject",
        "NtAssignProcessToJobObject", "NtTerminateJobObject",
        "NtFilterToken", "NtFilterTokenEx",
        "NtCompareTokens", "NtGetCurrentProcessorNumber",
        "NtPowerInformation", "NtDisplayString",
        "NtCreatePagingFile", "NtRaiseHardError",
        "NtContinue", "NtDebugActiveProcess",
        "NtYieldExecution", "NtTestAlert",
    ]
    
    # Also add Rtl functions
    rtl_funcs = [
        "RtlInitUnicodeString", "RtlInitAnsiString",
        "RtlAdjustPrivilege", "RtlGetVersion",
        "RtlCreateUserThread", "RtlAllocateHeap", "RtlFreeHeap",
        "RtlZeroMemory", "RtlCopyMemory", "RtlMoveMemory",
        "RtlFillMemory", "RtlCompareMemory",
        "RtlUpperChar", "RtlLowerChar",
        "RtlCompareString", "RtlCompareUnicodeString",
        "RtlEqualString", "RtlEqualUnicodeString",
        "RtlAppendUnicodeStringToString", "RtlAppendUnicodeToString",
        "RtlAnsiStringToUnicodeString", "RtlUnicodeStringToAnsiString",
        "RtlGUIDFromString", "RtlStringFromGUID",
        "RtlEncodePointer", "RtlDecodePointer",
        "RtlInitializeCriticalSection", "RtlEnterCriticalSection",
        "RtlLeaveCriticalSection", "RtlDeleteCriticalSection",
        "RtlRandomEx", "RtlUniform",
        "RtlCreateSecurityDescriptor", "RtlSetDaclSecurityDescriptor",
        "RtlGetDaclSecurityDescriptor", "RtlCopySecurityDescriptor",
        "RtlCreateAcl", "RtlAddAce", "RtlDeleteAce",
        "RtlAddAccessAllowedAce", "RtlAddAccessDeniedAce",
        "RtlAddAccessAllowedAceEx", "RtlAddAccessDeniedAceEx",
        "RtlAddMandatoryAce",
        "RtlWriteRegistryValue", "RtlDeleteRegistryValue",
        "RtlCreateRegistryKey", "RtlOpenRegistryKey",
    ]
    
    # Kernel32/other functions
    kernel_funcs = [
        "VirtualAlloc", "VirtualAllocEx", "VirtualProtect",
        "VirtualProtectEx", "VirtualFree", "VirtualFreeEx",
        "WriteProcessMemory", "ReadProcessMemory",
        "CreateRemoteThread", "CreateRemoteThreadEx",
        "CreateThread", "OpenProcess", "OpenThread",
        "CloseHandle", "GetModuleHandleA", "GetModuleHandleW",
        "GetProcAddress", "LoadLibraryA", "LoadLibraryW",
        "FreeLibrary", "GetModuleFileNameA", "GetModuleFileNameW",
        "CreateProcessA", "CreateProcessW",
        "CreateProcessInternalA", "CreateProcessInternalW",
        "GetCurrentProcessId", "GetCurrentThreadId",
        "Sleep", "SleepEx", "ExitProcess", "ExitThread",
        "GetLastError", "SetLastError",
        "WaitForSingleObject", "WaitForSingleObjectEx",
        "CreateFileA", "CreateFileW", "ReadFile", "WriteFile",
        "DeleteFileA", "DeleteFileW",
        "GetFileSize", "GetFileSizeEx",
        "FlushFileBuffers",
        "ExpandEnvironmentStringsA", "ExpandEnvironmentStringsW",
        "GetTempPathA", "GetTempPathW",
        "MultiByteToWideChar", "WideCharToMultiByte",
        "lstrlenA", "lstrlenW",
        "RegOpenKeyExA", "RegOpenKeyExW",
        "RegSetValueExA", "RegSetValueExW",
        "RegCloseKey", "RegCreateKeyExA", "RegCreateKeyExW",
        "AdjustTokenPrivileges", "OpenProcessToken",
        "LookupPrivilegeValueA", "LookupPrivilegeValueW",
        "GetTokenInformation", "DuplicateTokenEx",
        "ImpersonateLoggedOnUser", "RevertToSelf",
        "CreateProcessAsUserA", "CreateProcessAsUserW",
    ]
    
    all_funcs = ntdll_funcs + rtl_funcs + kernel_funcs
    
    for func in all_funcs:
        h = compute_hash(func, lowercase=False)
        hash_db[h] = f"Func: {func}"
        h_low = compute_hash(func, lowercase=True)
        if h_low != h:
            hash_db[h_low] = f"Func(lower): {func}"
    
    # === Match Against Target Hashes ===
    matches = {}
    for target_hash in list(func_hashes.keys()) + list(dll_hashes.keys()):
        if target_hash in hash_db:
            matches[target_hash] = hash_db[target_hash]
    
    results["hash_database_size"] = len(hash_db)
    results["resolved_matches"] = matches
    
    # === Unresolved hashes analysis ===
    unresolved_func = [h for h, v in func_hashes.items() if v["resolved"] is None]
    unresolved_dll = [h for h, v in dll_hashes.items() if v["resolved"] is None]
    
    results["unresolved_func_hashes"] = unresolved_func
    results["unresolved_dll_hashes"] = unresolved_dll
    
    # === Likely candidates for unresolved hashes ===
    # Based on the context (direct syscalls + file operations), the unresolved
    # syscall hashes likely correspond to:
    likely_candidates = {
        0x82a35258: {
            "candidates": ["NtWaitForSingleObject (for process monitoring)", "NtProtectVirtualMemory (for memory permission change)", "NtOpenFile (for opening existing file)"],
            "storage": "[0x180c51540]",
            "purpose": "syscall for waiting/protection/file opening",
        },
        0x427392e6: {
            "candidates": ["NtDelayExecution (for sleep/timing)", "NtFreeVirtualMemory (for cleanup)", "NtSetInformationProcess (for process manipulation)"],
            "storage": "[0x180c51544]",
            "purpose": "syscall for delay/memory cleanup/process info",
        },
        0xeb7a1a75: {
            "candidates": ["NtCreateUserProcess (for spawning child process)", "NtOpenProcessToken (for token manipulation)", "NtAllocateVirtualMemory (for memory allocation)"],
            "storage": "[0x180c5153c]",
            "purpose": "syscall for process creation/token/memory",
        },
        0x79468157: {
            "candidates": ["RtlInitUnicodeString (for string init)", "LdrLoadDll (for DLL loading)", "NtOpenProcess (for process access)"],
            "storage": "[0x180c51548]",
            "purpose": "function pointer - likely for DLL loading or process operations",
        },
        0x77a3ed30: {
            "candidates": ["RtlAdjustPrivilege (for privilege escalation)", "NtAdjustPrivilegesToken (for token adjustment)", "LdrGetProcedureAddress (for function resolution)"],
            "storage": "[0x180c51550]",
            "purpose": "function pointer - likely for privilege/API resolution",
        },
        0x5435a0bf: {
            "candidates": ["NtCreateSection (for shared memory)", "NtMapViewOfSection (for memory mapping)", "VirtualAlloc (for memory allocation)"],
            "storage": "[0x180c51558]",
            "purpose": "function pointer - likely for memory mapping",
        },
        0xceb013a2: {
            "candidates": ["NtWriteVirtualMemory (for memory writing)", "NtCreateThreadEx (for thread creation)", "RtlCreateUserThread (for remote thread)"],
            "storage": "[0x180c51560]",
            "purpose": "function pointer - likely for code injection",
        },
        0x46ca3d07: {
            "candidates": ["NTDLL.DLL (via alternate Unicode encoding)", "KERNEL32.DLL (via alternate path)", "api-ms-win-core-synch API set"],
            "purpose": "DLL hash - likely a core Windows module",
        },
    }
    
    results["likely_candidates"] = likely_candidates
    
    # === Algorithm Verification ===
    # Verify our hash algorithm works by checking known values
    verification = {}
    verification["NtCreateFile"] = hex(compute_hash("NtCreateFile"))
    verification["NtWriteFile"] = hex(compute_hash("NtWriteFile"))
    verification["NtClose"] = hex(compute_hash("NtClose"))
    verification["KERNEL32_DLL_uppercase"] = hex(compute_hash_unicode("KERNEL32.DLL"))
    verification["KERNEL32_DLL_lowercase"] = hex(compute_hash("KERNEL32.DLL", lowercase=True))
    verification["NTDLL_DLL_uppercase"] = hex(compute_hash_unicode("NTDLL.DLL"))
    verification["NTDLL_DLL_lowercase"] = hex(compute_hash("ntdll.dll", lowercase=True))
    verification["IDLL_DLL_uppercase"] = hex(compute_hash_unicode("IDLL.DLL"))
    verification["IDLL_DLL_lowercase"] = hex(compute_hash("idll.dll", lowercase=True))
    
    results["algorithm_verification"] = verification
    
    # === Save ===
    out_file = os.path.join(OUT_DIR, "hash_resolution.json")
    with open(out_file, "w") as f:
        json.dump(results, f, indent=2)
    print(f"[+] Hash resolution saved to {out_file}")
    
    # === Human-readable report ===
    report_file = os.path.join(OUT_DIR, "hash_resolution_report.txt")
    with open(report_file, "w") as f:
        f.write("=" * 70 + "\n")
        f.write("  API HASH RESOLUTION REPORT\n")
        f.write("=" * 70 + "\n\n")
        
        f.write("--- Algorithm ---\n")
        f.write("  Formula: hash = 0xe7A1; hash = hash * 0x21 + char\n")
        f.write("  DLL names: Unicode WCHAR, converted to uppercase\n")
        f.write("  Function names: ANSI chars, no case conversion\n\n")
        
        f.write("--- Verification (Known Values) ---\n")
        for name, h in verification.items():
            f.write(f"  {name}: {h}\n")
        f.write("\n")
        
        f.write("--- Resolved Hashes ---\n")
        for h, name in matches.items():
            f.write(f"  0x{h:x} -> {name}\n")
        f.write("\n")
        
        f.write("--- Unresolved Function Hashes ---\n")
        for h in unresolved_func:
            f.write(f"  0x{h:x}\n")
        f.write("\n")
        
        f.write("--- Unresolved DLL Hashes ---\n")
        for h in unresolved_dll:
            f.write(f"  0x{h:x}\n")
        f.write("\n")
        
        f.write("--- Likely Candidates for Unresolved ---\n")
        for h, info in likely_candidates.items():
            f.write(f"  0x{h:x} ({info.get('storage', '')}):\n")
            for cand in info.get("candidates", []):
                f.write(f"    - {cand}\n")
            f.write(f"    Purpose: {info.get('purpose', '')}\n\n")
        
        f.write("--- Note ---\n")
        f.write("  The remaining unresolved hashes may correspond to:\n")
        f.write("  - Functions with slightly different naming conventions\n")
        f.write("  - Internal/undocumented ntdll functions\n")
        f.write("  - Functions from the second resolved DLL module\n")
        f.write("  Full resolution requires runtime emulation or sandbox execution\n")
    
    print(f"[+] Hash resolution report saved to {report_file}")

if __name__ == "__main__":
    main()