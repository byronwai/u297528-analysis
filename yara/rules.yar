rule idll_dll_loader {
    meta:
        description = "Detects idll.dll DLL side-loading malware loader"
        author = "sandbox-analysis"
        date = "2026-05-21"
        severity = "HIGH"
    strings:
        $idll = "IdllEntry" ascii wide
        $idll_name = "idll.dll" ascii wide
    condition:
        $idll and $idll_name
}

rule idll_dll_syscall_stubs {
    meta:
        description = "Detects direct syscall stubs used for EDR bypass"
        author = "sandbox-analysis"
        date = "2026-05-21"
        severity = "HIGH"
    strings:
        $syscall_ret = { 0f 05 c3 }
        $mov_r10_rcx = { 4c 8b d1 }
    condition:
        $mov_r10_rcx and $syscall_ret and filesize > 5MB
}

rule idll_dll_peb_walker {
    meta:
        description = "Detects PEB walking for hash-based API resolution"
        author = "sandbox-analysis"
        date = "2026-05-21"
        severity = "HIGH"
    strings:
        $gs_60 = { 65 48 8b 04 25 60 00 00 00 }
        $peb_ldr = { 48 8b 58 18 }
        $hash_mul = { 6b c0 21 }
        $hash_init = { b8 a1 e7 00 00 }
    condition:
        $gs_60 and $peb_ldr and $hash_mul and $hash_init
}

rule idll_dll_xor_decrypt {
    meta:
        description = "Detects position-dependent XOR cipher"
        author = "sandbox-analysis"
        date = "2026-05-21"
        severity = "MEDIUM"
    strings:
        $xor_3d = { 34 3d }
        $xor_7a = { 34 7a }
        $xor_b7 = { 34 b7 }
    condition:
        2 of ($xor_3d, $xor_7a, $xor_b7)
}

rule idll_dll_minimal_imports_and_large_data {
    meta:
        description = "Detects PE DLL with minimal imports and large data section"
        author = "sandbox-analysis"
        date = "2026-05-21"
        severity = "MEDIUM"
    strings:
        $kernel32 = "KERNEL32.dll" ascii wide
        $disable_thread = "DisableThreadLibraryCalls" ascii wide
    condition:
        $kernel32 and $disable_thread and filesize > 5MB
}