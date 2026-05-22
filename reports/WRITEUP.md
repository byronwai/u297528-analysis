# Malware Analysis Writeup: Decrypting the idll.dll USB Dropper

## Executive Summary

A suspicious DLL file (`u297528.dat`, 12.6 MB) was discovered on a USB device and analyzed through static reverse engineering. The file is a PE32+ DLL named `idll.dll` that employs multiple evasion layers — hash-based API resolution via PEB walking, direct syscall execution, a custom position-dependent XOR cipher, and AES-256-CBC encryption — to hide and deploy a 6.81 MB payload containing a dropper with **18 embedded PE files**. This writeup details the full analysis methodology and the step-by-step process that led to successful decryption.

---

## 1. Initial Triage

### 1.1 File Identification

```bash
$ file u297528.dat
PE32+ executable (DLL) (GUI) x86-64, 4 sections
```

```python
import pefile
pe = pefile.PE('u297528.dat')
print(f"Export: {pe.DIRECTORY_ENTRY_EXPORT.symbols[0].name.decode()}")
# Export: IdllEntry
print(f"Entry Point RVA: 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:x}")
# Entry Point RVA: 0x2820
```

Key observations:
- Only **3 imports** from KERNEL32.dll: `GetModuleFileNameW`, `GetModuleHandleExW`, `DisableThreadLibraryCalls`
- **12.5 MB .data section** — wildly disproportionate to the 12 KB .text section
- Export name `IdllEntry` and DLL name `idll.dll` — classic DLL side-loading indicator

### 1.2 Section Layout

| Section | VA | Raw Size | Notes |
|---------|----|----------|-------|
| `.text` | 0x1000 | 12 KB | Code (very small) |
| `.rdata` | 0x4000 | 2 KB | Read-only data |
| `.data` | 0x5000 | **12.5 MB** | Encrypted payload |
| `.pdata` | 0xC52000 | 4 KB | Exception info |

---

## 2. Evasion Technique #1: Hash-Based API Resolution

The DLL resolves Windows API functions at runtime by walking the PEB (Process Environment Block) and computing a custom hash over DLL and function names — completely bypassing the Import Address Table.

### 2.1 The Hash Algorithm

Disassembly of the PEB walker at `0x180003c90`:

```asm
; Walk PEB -> Ldr -> InMemoryOrderModuleList
180003920:   imul   eax,eax,0x21        ; hash *= 0x21
180003923:   lea    r8,[r8+0x1]          ; advance to next char
180003927:   movsx  ecx,cl               ; sign-extend current char
18000392a:   add    eax,ecx              ; hash += char
18000392c:   movzx  ecx,BYTE PTR [r8]    ; load next char
180003930:   test   cl,cl                ; null terminator?
180003932:   jne    0x180003920          ; loop if not null
```

The algorithm in Python:

```python
def compute_hash(name, seed=0xe7A1, multiplier=0x21):
    h = seed
    for ch in name:
        h = (h * multiplier + ord(ch)) & 0xFFFFFFFF
    return h
```

DLL names are converted to **uppercase Unicode (WCHAR)** before hashing; function names use ANSI chars as-is.

### 2.2 Resolved API Hashes

The resolved hashes are then compared against hardcoded constants:

```asm
180003936:   cmp    eax,0x695b8977       ; NtCreateFile
180003952:   cmp    eax,0x4d799fce       ; NtWriteFile
18000396e:   cmp    eax,0x82a35258       ; NtWaitForSingleObject
18000398a:   cmp    eax,0x427392e6       ; NtDelayExecution
1800039a6:   cmp    eax,0x844c5e59       ; NtClose
1800039bf:   cmp    eax,0xeb7a1a75       ; NtCreateUserProcess
```

When a hash matches, the malware extracts the **syscall number** from byte offset +4 of the resolved function stub and stores it:

```asm
180003942:   movzx  eax,BYTE PTR [r9+0x4]    ; read syscall number from ntdll stub
180003947:   mov    DWORD PTR [rip+0xc4dbe3],eax  ; store at 0x180c51530
```

---

## 3. Evasion Technique #2: Direct Syscall Execution

All NT API calls use raw `syscall` instructions with pre-resolved syscall numbers — completely bypassing EDR hooks on `ntdll.dll` exported stubs.

### 3.1 Syscall Stub Pattern

Six identical stubs at `0x180003f30`–`0x180003f6c`:

```asm
; Syscall stub for NtCreateFile
180003f30:   mov    r10,rcx                    ; Windows x64 syscall convention
180003f33:   mov    eax,DWORD PTR [rip+0xc4d5f7]  ; load syscall number from 0x180c51530
180003f39:   syscall                            ; direct kernel call
180003f3b:   ret

; Syscall stub for NtWriteFile
180003f3c:   mov    r10,rcx
180003f3f:   mov    eax,DWORD PTR [rip+0xc4d5ef]  ; load from 0x180c51534
180003f45:   syscall
180003f47:   ret
```

The syscall numbers are resolved dynamically at runtime by reading byte offset +4 from the real `ntdll.dll` stubs, making the malware **version-independent**.

---

## 4. The Entry Point: IdllEntry

The export `IdllEntry` at RVA `0x2840` is the real execution entry. It performs an anti-analysis check before proceeding:

```asm
180002840:   test   r8,r8                     ; check parameter exists
180002843:   je     0x180003807               ; bail if null
180002849:   push   rbp
18000284a:   lea    rbp,[rsp-0xab0]           ; large stack frame (2,736 bytes)
180002852:   sub    rsp,0xbb0                 ; allocate 3,000 bytes
180002859:   cmp    BYTE PTR [r8],0x31        ; check parameter == '1' (0x31)
18000285d:   jne    0x1800037ff               ; bail if not '1'
180002863:   call   0x180003da0               ; resolve ntdll via hash
```

The check for byte `0x31` ('1') means the DLL must be called with a specific argument — a rudimentary anti-execution guard.

After validation, IdllEntry:

1. Resolves `ntdll.dll` and a second DLL via PEB hash walking
2. Extracts syscall numbers from resolved ntdll stubs
3. Builds a **substitution table** with ~310 hardcoded WORD entries on the stack
4. Calls the **position-dependent XOR decrypt** function to decode the table
5. Uses the decoded table + direct syscalls to **decrypt the AES payload**, write it to disk, and execute it

---

## 5. Evasion Technique #3: Position-Dependent XOR Cipher

### 5.1 The XOR Decrypt Function

At `0x180001a10`, a custom cipher decodes the substitution table:

```asm
180001a10:   cmp    BYTE PTR [rcx+0x1],0x0     ; check if already decoded
180001a14:   mov    r8,rcx                       ; save base pointer
180001a17:   jne    0x180001b66                  ; skip if already initialized
180001a1d:   movzx  edx,BYTE PTR [rcx]           ; key_byte = struct[0]
180001a20:   movzx  eax,dl
180001a23:   xor    al,BYTE PTR [rcx+0x2]        ; al = key XOR data[2]
180001a26:   movzx  eax,al
180001a29:   mov    WORD PTR [rcx+0x2],ax        ; store as WORD
180001a2d:   movzx  eax,dl
180001a30:   xor    al,BYTE PTR [rcx+0x4]        ; al = key XOR data[4]
180001a33:   xor    al,0x3d                       ; XOR with constant 0x3D
180001a35:   movzx  eax,al
180001a38:   mov    WORD PTR [rcx+0x4],ax
180001a3f:   xor    al,BYTE PTR [rcx+0x6]
180001a42:   xor    al,0x7a                       ; XOR with constant 0x7A
...
```

### 5.2 Discovering the Arithmetic Sequence

Extracting all XOR constants from the disassembly revealed a pattern:

```python
# Extracted constants from 0x180001a10:
# 0x3d, 0x7a, 0xb7, 0xf4, 0x31, 0x6e, 0xab, 0xe8, 0x25, 0x62, 0x9f, 0xdc, ...

# Test: are these multiples of 0x3D mod 256?
for i in range(20):
    val = (0x3D * (i + 1)) & 0xFF
    print(f"  i={i:2d}: 0x{val:02x}")

# Output matches perfectly:
#   i= 0: 0x3d  i= 1: 0x7a  i= 2: 0xb7  i= 3: 0xf4
#   i= 4: 0x31  i= 5: 0x6e  i= 6: 0xab  i= 7: 0xe8
#   i= 8: 0x25  i= 9: 0x62  i=10: 0x9f  i=11: 0xdc
```

The complete formula:

```python
def xor_constant(i):
    """Position-dependent XOR constant"""
    return (0x3D * (i + 1)) & 0xFF

def xor_decrypt(data, key_byte):
    """Decode substitution table entry"""
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = (key_byte ^ data[i]) ^ xor_constant(i)
    return result
```

---

## 6. The AES-256-CBC Payload Encryption

### 6.1 Identifying AES

The `.rdata` section at RVA `0x4020` contains the **standard AES S-box** (256 bytes starting with `63 7c 77 7b f2 6b 6f c5`), and at RVA `0x4120` the **AES inverse S-box** (starting with `52 09 6a d5 30 36 a5 38`). The function at `0x1800010d0` implements full AES key expansion (SubWord, RotWord, AddRoundKey with the S-box at `0x180004120`).

### 6.2 Tracing the AES Key Through IdllEntry

The critical breakthrough came from tracing `lea` instructions near the AES decrypt call at `0x180001000`:

```asm
; Load addresses of key material from .data section
180003107:   lea    r8,[rip+0x57dffa]        ; -> 0x180581108 (AES IV)
18000310e:   lea    rdx,[rip+0x57dfd3]       ; -> 0x1805810e8 (AES Key)
18000311d:   lea    rcx,[rbp+0x990]          ; output key schedule buffer
180003124:   call   0x1800010a0              ; AES key expansion

; Decrypt the payload
180003129:   mov    r8d,0x6d0410             ; payload size = 7,144,464 bytes
18000312f:   lea    rdx,[rip+0x57dfea]       ; -> 0x180581120 (encrypted payload)
180003136:   lea    rcx,[rbp+0x990]          ; expanded key
18000313d:   call   0x180001000              ; AES-256-CBC decrypt
```

### 6.3 Extracting Key and IV

Reading the .data section at the traced addresses:

```python
import pefile

pe = pefile.PE('u297528.dat')
data_section = [s for s in pe.sections if s.Name.rstrip(b'\x00') == b'.data'][0]
data_raw = data_section.get_data()

# AES-256 key at .data+0x57c0e8 (32 bytes)
aes_key_256 = data_raw[0x57c0e8:0x57c0e8 + 32]
# b1fa3fd02d8ec02302cf4ce7a46957f76eaaa7c5a73b3d2cb6bcb4a322593180

# AES-128 IV at .data+0x57c108 (16 bytes)
aes_iv = data_raw[0x57c108:0x57c108 + 16]
# 815f73d17e0ab351296629a197d378a5
```

### 6.4 Decrypting the Payload

```python
from Crypto.Cipher import AES

# Key and IV
aes_key_256 = bytes.fromhex("b1fa3fd02d8ec02302cf4ce7a46957f7"
                             "6eaaa7c5a73b3d2cb6bcb4a322593180")
aes_iv = bytes.fromhex("815f73d17e0ab351296629a197d378a5")

# Encrypted payload at .data+0x57c120
payload_offset = 0x57c120
payload_size = 0x6d0410  # 7,144,464 bytes
encrypted = data_raw[payload_offset:payload_offset + payload_size]

# Pad to AES block size
pad_len = (16 - len(encrypted) % 16) % 16
encrypted_padded = encrypted + b'\x00' * pad_len

# Decrypt with AES-256-CBC
cipher = AES.new(aes_key_256, AES.MODE_CBC, aes_iv)
decrypted = cipher.decrypt(encrypted_padded)[:payload_size]

# Verify PE header
assert decrypted[:2] == b'MZ', "Decryption failed!"
print(f"[+] PE HEADER CONFIRMED! Payload decrypted successfully.")
```

---

## 7. Decrypted Payload Analysis

The decrypted payload is a **PE32+ x86-64 Windows GUI executable**:

| Property | Value |
|----------|-------|
| Machine | x86-64 (0x8664) |
| Timestamp | 0x697b3902 (2026-01-29) |
| Entry Point | 0xa304 |
| Image Base | 0x140000000 |
| Image Size | 6.84 MB |
| **MD5** | `e10a9bb09acb415e5dc8654b8593a45c` |
| **SHA256** | `d59e83b0be737896dec8b91c7a52f87e16f83e911af52826b98481b5c50f32b2` |

### 7.1 Sections

| Section | VA | Virtual Size | Notes |
|---------|----|-------------|-------|
| `.text` | 0x1000 | 144 KB | Code |
| `.rdata` | 0x25000 | **6.7 MB** | Contains **18 embedded PE files** |
| `.data` | 0x6cd000 | 10 KB | Global data |
| `.pdata` | 0x6d0000 | 9 KB | Exception info |
| `.fptable` | 0x6d3000 | 256 B | Function pointers |
| `.rsrc` | 0x6d4000 | 488 B | Resources |
| `.reloc` | 0x6d5000 | 2.4 KB | Relocations |

### 7.2 Imports

| DLL | Functions | Purpose |
|-----|-----------|---------|
| KERNEL32.dll | 95 | File, process, memory operations |
| ADVAPI32.dll | 3 | Registry manipulation (`RegSetValueExW`, `RegOpenKeyExW`, `RegCloseKey`) |
| ole32.dll | 3 | COM object creation (`CoCreateInstance`, `CoInitializeEx`, `CoUninitialize`) |
| OLEAUT32.dll | 3 | OLE automation (`VariantClear`, `SysAllocString`, `SysFreeString`) |

The 18 embedded PE files within the massive `.rdata` section strongly indicate this is a **multi-stage dropper** that extracts and executes additional payloads — potentially a cryptocurrency miner (matching the USB trap crypto mining blog reference) or a loader framework.

---

## 8. YARA Detection Rules

```yara
rule idll_dll_loader {
    meta:
        description = "Detects idll.dll DLL side-loading malware loader"
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
        severity = "MEDIUM"
    strings:
        $kernel32 = "KERNEL32.dll" ascii wide
        $disable_thread = "DisableThreadLibraryCalls" ascii wide
    condition:
        $kernel32 and $disable_thread and filesize > 5MB
}
```

All 5 rules match the original `u297528.dat` sample.

---

## 9. Complete Execution Flow

```
USB Device
  |
  v
[idll.dll loaded via DLL side-loading]
  |
  v
DllMain (0x180002820)
  |-- DisableThreadLibraryCalls()
  |-- return TRUE (minimal, no action)
  |
  v
IdllEntry (0x180002840) called with param='1'
  |
  |-- Check parameter == 0x31 ('1')
  |-- Resolve ntdll.dll via PEB hash walking (0x40583309)
  |-- Resolve second DLL via hash (0x46ca3d07)
  |-- Extract syscall numbers from ntdll stubs [+4 offset]
  |-- Build substitution table (~310 WORD values) on stack
  |-- Call XOR decrypt (0x180001a10) to decode table
  |      formula: decoded[i] = (key_byte ^ data[i]) ^ (0x3D*(i+1) & 0xFF)
  |
  |-- Load AES-256 key from .data+0x57c0e8 (32 bytes)
  |-- Load AES IV from .data+0x57c108 (16 bytes)
  |-- Expand AES key schedule (0x1800010a0)
  |-- AES-256-CBC decrypt payload at .data+0x57c120 (7,144,464 bytes)
  |
  |-- NtCreateFile (syscall) -> create temp file on disk
  |-- NtWriteFile (syscall) -> write decrypted PE to file
  |-- NtCreateUserProcess (syscall) -> execute dropped file
  |-- NtWaitForSingleObject (syscall) -> monitor child process
  |-- NtClose (syscall) -> cleanup
  |-- NtDelayExecution (syscall) -> sleep
  |
  v
[Decrypted payload executes]
  |-- Drops 18 embedded PE files from .rdata
  |-- Modifies registry (ADVAPI32.dll)
  |-- Creates COM objects (ole32.dll)
  |-- Likely cryptocurrency miner or multi-stage loader
```

---

## 10. Indicators of Compromise (IOCs)

| IOC | Value |
|-----|-------|
| DLL Name | `idll.dll` |
| Export | `IdllEntry` |
| Original File MD5 | `dbd8dbecaa80795c135137d69921fdba` |
| Original File SHA256 | `e60ab99da105ee27ee09ea64ed8eb46d8edc92ee37f039dbc3e2bb9f587a33ba` |
| Decrypted Payload MD5 | `e10a9bb09acb415e5dc8654b8593a45c` |
| Decrypted Payload SHA256 | `d59e83b0be737896dec8b91c7a52f87e16f83e911af52826b98481b5c50f32b2` |
| AES-256 Key | `b1fa3fd02d8ec02302cf4ce7a46957f76eaaa7c5a73b3d2cb6bcb4a322593180` |
| AES IV | `815f73d17e0ab351296629a197d378a5` |
| API Hash Seed | `0xe7A1` |
| API Hash Multiplier | `0x21` |
| PE Timestamp | `0x697b3982` (2026-01-29 05:42:10 UTC) |
| Syscall Stub Range | `0x180003f30`–`0x180003f6c` |
| XOR Decrypt Function | `0x180001a10` |
| Payload Size | `0x6d0410` (7,144,464 bytes) |

---

## 11. Detailed Next Steps

### Step 1: Analyze the 18 Embedded PE Files

The decrypted payload's `.rdata` section (6.7 MB) contains 18 `MZ` signatures. These are the real malware components.

```bash
# Extract all embedded PE files from the decrypted payload
python3 -c "
import pefile
pe = pefile.PE('findings/decrypted_payload.exe')
for s in pe.sections:
    if s.Name.rstrip(b'\x00') == b'.rdata':
        rdata = s.get_data()
        pos = 0
        idx = 0
        while True:
            pos = rdata.find(b'MZ', pos)
            if pos == -1: break
            # Verify it has a valid PE header
            if pos + 0x3c + 4 < len(rdata):
                pe_off = int.from_bytes(rdata[pos+0x3c:pos+0x40], 'little')
                if pos + pe_off + 4 < len(rdata) and rdata[pos+pe_off:pos+pe_off+4] == b'PE\x00\x00':
                    with open(f'findings/embedded_pe_{idx}.bin', 'wb') as f:
                        f.write(rdata[pos:])  # truncate - need size calc
                    idx += 1
            pos += 1
"
```

**Action items:**
- Determine file type and purpose of each embedded PE
- Check for additional encryption layers within embedded files
- Cross-reference hashes with VirusTotal

### Step 2: Dynamic Analysis in a Sandboxed Environment

Set up a controlled Windows x64 VM with monitoring:

```bash
# Option A: CAPE Sandbox (Docker)
docker pull cape/sandbox
docker run -d -p 8000:8000 cape/sandbox

# Option B: Cuckoo Sandbox
pip3 install cuckoo
cuckoo init
cuckoo community
```

**Monitor specifically:**
- File system activity: what files are dropped and where
- Registry modifications via `RegSetValueExW`
- Network connections (potential C2 beacons)
- Process tree from `NtCreateUserProcess`
- COM objects created via `CoCreateInstance`

### Step 3: VirusTotal and Threat Intelligence Lookup

```bash
# Submit both the original DLL and decrypted payload
curl -X POST "https://www.virustotal.com/api/v3/files" \
  -H "x-apikey: YOUR_API_KEY" \
  -F "file=@findings/decrypted_payload.exe"

# Check the embedded PE hashes
for f in findings/embedded_pe_*.bin; do
    sha256=$(sha256sum "$f" | awk '{print $1}')
    curl "https://www.virustotal.com/api/v3/files/$sha256" \
      -H "x-apikey: YOUR_API_KEY"
done
```

### Step 4: Network Indicator Extraction

Search the decrypted payload for C2 infrastructure:

```bash
# Extract IP addresses and domains
strings -n 8 findings/decrypted_payload.exe | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
strings -n 8 findings/decrypted_payload.exe | grep -oE '[a-zA-Z0-9.-]+\.(com|net|org|io|xyz|top)'
strings -n 8 findings/decrypted_payload.exe | grep -oE 'https?://[^"]+'
```

### Step 5: Write Detection YARA Rules for the Decrypted Payload

```yara
rule decrypted_dropper_payload {
    meta:
        description = "Detects the decrypted dropper from idll.dll USB malware"
    strings:
        $mz = "MZ"
        $s1 = "MultiByteToWideChar" ascii wide
        $s2 = "RegSetValueExW" ascii wide
        $s3 = "CoCreateInstance" ascii wide
        $mutex = "CreateMutexW" ascii wide
    condition:
        $mz at 0 and all of ($s1, $s2, $s3) and filesize > 5MB
}
```

### Step 6: Correlate with the Referenced Blog

The original blog at `https://imaginary-paw-91f.notion.site/Infected-USB-3578a8ab5bdf807aac39d6e4308bf966` (which required JavaScript and could not be fetched during analysis) should be revisited via a browser. Key questions to answer:
- Does the blog describe the same malware family?
- Are there other samples in the same campaign?
- What was the infection vector (bait USB, supply-chain, etc.)?
- Is the cryptocurrency mining angle confirmed?

### Step 7: Build a Full Deobfuscation Script

Consolidate all analysis into a single re-runnable script:

```python
#!/usr/bin/env python3
"""Full deobfuscation pipeline for idll.dll (u297528.dat)"""
import pefile
from Crypto.Cipher import AES

def decrypt_idll_dll(filepath, output_path):
    pe = pefile.PE(filepath)
    data_raw = [s for s in pe.sections
                if s.Name.rstrip(b'\x00') == b'.data'][0].get_data()

    key = bytes.fromhex("b1fa3fd02d8ec02302cf4ce7a46957f7"
                         "6eaaa7c5a73b3d2cb6bcb4a322593180")
    iv  = bytes.fromhex("815f73d17e0ab351296629a197d378a5")

    encrypted = data_raw[0x57c120:0x57c120 + 0x6d0410]
    pad = (16 - len(encrypted) % 16) % 16
    encrypted += b'\x00' * pad

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(encrypted)[:0x6d0410]

    assert decrypted[:2] == b'MZ', "Decryption failed!"
    with open(output_path, 'wb') as f:
        f.write(decrypted)
    print(f"[+] Payload decrypted to {output_path}")
    pe.close()

if __name__ == '__main__':
    decrypt_idll_dll('u297528.dat', 'decrypted_payload.exe')
```

---

## 12. Tools Used

| Tool | Purpose |
|------|---------|
| `pefile` (Python) | PE parsing, section extraction, hash computation |
| `objdump` | Disassembly of x86-64 code |
| `radare2` | Interactive disassembly and analysis |
| `YARA 4.5.5` | Signature-based detection |
| `Ghidra 12.1` | Headless analysis and decompilation (Java scripts) |
| `pycryptodome` | AES-256-CBC decryption |
| `strings` / `xxd` | String extraction and hex dumping |
| `Python 3.13` | Scripting and automation |

---

## 13. Files Generated

All artifacts saved to `/home/kali/Downloads/sandbox/findings/`:

| File | Size | Description |
|------|------|-------------|
| `decrypted_payload.exe` | 6.81 MB | **Successfully decrypted PE payload** |
| `DECRYPTION_REPORT.txt` | 3.7 KB | Decryption summary report |
| `decryption_results.json` | 0.5 KB | Structured decryption metadata |
| `yara_rules.yar` | 1.9 KB | 5 YARA detection rules |
| `yara_results.txt` | 9.3 KB | Detailed YARA match output |
| `idllentry_disasm.txt` | 47 KB | Full IdllEntry disassembly (881 lines) |
| `SUMMARY.txt` | 4.1 KB | Original analysis summary |
| `summary_checkpoint.json` | 5.1 KB | Original structured findings |
