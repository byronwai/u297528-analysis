# Miner Analysis Writeup: PrintMiner — From Decrypted Payload to Monero Wallet

## Executive Summary

After successfully decrypting the AES-256-CBC payload from `idll.dll` (detailed in the [Initial Analysis Writeup](01_INITIAL_ANALYSIS.md)), the decrypted 6.81 MB executable was identified as a multi-stage dropper deploying **PrintMiner** — a Monero (XMR) cryptocurrency miner spread via infected USB drives. This writeup covers the complete post-decryption analysis: embedded PE extraction, VirusTotal correlation, sandbox behavioral analysis, mining pool identification, and the search for the wallet address. Our findings are corroborated by [AhnLab ASEC's independent report](https://asec.ahnlab.com/en/91415/) on the same malware family.

---

## 1. Analysis Workflow Overview

```
Decrypted Payload (6.81 MB PE)
  |
  v
[1. PE Structure Analysis]  →  2 valid embedded PEs found (not 18)
  |
  v
[2. Embedded PE Extraction]  →  Miner (230 KB) + Dropper (6.3 MB)
  |
  v
[3. VirusTotal Submission]  →  All 4 files submitted, family identified
  |                               Detection: 8-77% across engines
  |                               Classification: trojan.tedy / BitcoinMiner
  v
[4. Sandbox Behavioral Analysis]  →  VT Jujubox + CAPE + C2AE
  |                                    Self-deletion, service install,
  |                                    Defender exclusion, PowerShell
  v
[5. MITRE ATT&CK Mapping]  →  T1027 (XOR/AES/RC4), T1497 (anti-VM),
  |                            T1543.003 (service persistence), T1569.002
  v
[6. Network Indicator Extraction]  →  No plaintext wallet found
  |                                   Config encrypted with RC4
  v
[7. Threat Intelligence Correlation]  →  AhnLab ASEC: PrintMiner family
  |                                       Same code, same behavior, same IOCs
  v
[8. Mining Pool & Wallet Identification]  →  Pool: r2.hashpoolpx.net:443
                                             Wallet: fetched from C2 at runtime
```

---

## 2. Embedded PE Extraction

### 2.1 Why Not 18 PEs?

The initial analysis counted 18 `MZ` signatures in the `.rdata` section. However, many of these are false positives — partial PE headers embedded within the larger PE files. Valid PEs require both an `MZ` header **and** a valid `PE\x00\x00` signature at the offset indicated by `e_lfanew`.

```python
def find_pe_files(data):
    """Find all valid PE files within a data blob"""
    pes = []
    pos = 0
    while True:
        pos = data.find(b'MZ', pos)
        if pos == -1:
            break
        # Validate PE header — not just MZ, but MZ + valid PE offset
        if pos + 0x40 < len(data):
            pe_offset_bytes = data[pos + 0x3c:pos + 0x40]
            if len(pe_offset_bytes) == 4:
                pe_off = struct.unpack_from('<I', pe_offset_bytes)[0]
                if 0x40 <= pe_off < 0x1000 and pos + pe_off + 4 <= len(data):
                    if data[pos + pe_off:pos + pe_off + 4] == b'PE\x00\x00':
                        pes.append(pos)
        pos += 1
    return pes
```

**Result: Only 2 valid embedded PEs** were found.

### 2.2 Extracted Components

| # | Size | Machine | Entropy | Role |
|---|------|---------|---------|------|
| `embedded_00.bin` | 230 KB | x86-64 | 5.71 | **Miner component** |
| `embedded_01.bin` | 6.3 MB | x86-64 | 5.98 | **Main dropper with networking** |

```python
# Extract with pefile and calculate exact PE size
pe = pefile.PE(data=pe_data)
actual_size = 0
for s in inner_pe.sections:
    end = s.PointerToRawData + s.SizeOfRawData
    if end > actual_size:
        actual_size = end
actual_size = max(actual_size, inner_pe.OPTIONAL_HEADER.SizeOfHeaders)
pe_data = pe_data[:actual_size]
```

### 2.3 Component Identification

**embedded_01.bin (Dropper)** — The main orchestrator:
- Imports **WS2_32.dll** with **48 socket functions** — extensive networking
- Imports **WTSAPI32.dll** (Terminal Services) and **NETAPI32.dll** (network management)
- Contains wide strings: `wlogz.dat`, `wsvcz`, `C:\Windows\System32\`, error messages
- Uses **nlohmann::json** (C++ JSON library) for config parsing
- Uses **asio** (C++ networking library) for async I/O
- Contains **libcurl** references (HTTP/HTTPS client)

**embedded_00.bin (Miner)** — The actual XMRig-based miner:
- 7 sections, small `.data` (5 KB)
- References `dxgi.dll` (GPU detection), `ntdll.dll`
- Contains `GetUserDefaultLocaleName` (locale-based behavior)

---

## 3. VirusTotal Analysis

### 3.1 Submission and Detection Results

All 4 files were submitted to VirusTotal via the v3 API:

```python
import requests

VT_API_KEY = "<REDACTED>"
HEADERS = {"x-apikey": VT_API_KEY}

# Submit each file
files = {
    "u297528.dat": open("u297528.dat", "rb"),
    "decrypted_payload.exe": open("data/decrypted_payload.exe", "rb"),
    "embedded_00.bin": open("data/embedded_pes/embedded_00.bin", "rb"),
    "embedded_01.bin": open("data/embedded_pes/embedded_01.bin", "rb"),
}

for name, f in files.items():
    resp = requests.post("https://www.virustotal.com/api/v3/files",
                         headers=HEADERS, files={"file": f})
    analysis_id = resp.json()["data"]["id"]
    print(f"  {name}: {analysis_id}")
```

### 3.2 Detection Summary

| File | Detection | Key Classification |
|------|-----------|-------------------|
| `u297528.dat` (original DLL) | **55/71 (77.5%)** | `trojan.genericfca/agentb`, tags: `spreader`, `detect-debug-environment` |
| `decrypted_payload.exe` | **38/71 (53.5%)** | `trojan.tedy/misc`, tags: `persistence`, `overlay` |
| `embedded_00.bin` (miner) | **8/71 (11.3%)** | `Trojan.BitCoinMiner`, `Trojan[Miner]/Win32.BitCoinMiner` |
| `embedded_01.bin` (dropper) | **54/70 (77.1%)** | `Trojan.BitcoinMiner`, `BehavesLike.Win64.Dropper.vh` |

The lower detection rate for `embedded_00.bin` (11.3%) indicates the miner component is **more evasive** — likely a custom-compiled XMRig variant with obfuscated config handling.

### 3.3 Key Detections Revealing Malware Type

```
CAT-QuickHeal:     Trojan.Coinminer.S38826036        ← CoinMiner
Zillya:            Trojan.BitCoinMiner.Win32.1739     ← BitcoinMiner (generic label)
Antiy-AVL:         Trojan[Miner]/Win32.BitCoinMiner   ← Miner
Gridinsoft:        Trojan.Win64.CoinMiner.dd!s1       ← CoinMiner
Microsoft:         Trojan:Win32/Wacatac.B!ml          ← Generic trojan
CrowdStrike:       win/malicious_confidence_100% (D)  ← High confidence
```

> **Note:** Many engines label this as "BitcoinMiner" generically. In reality, this is a **Monero (XMR)** miner — the `BitCoinMiner` label is a common misnomer in AV engines for any cryptocurrency miner.

---

## 4. Sandbox Behavioral Analysis

### 4.1 VirusTotal Jujubox — Decrypted Payload Execution

When the decrypted payload is executed in the Jujubox sandbox:

```
decrypted_payload.exe (PID 2996)
  ├── cmd.exe /c timeout /t 5 /nobreak && del /q <self> (PID 648)
  │     └── timeout /t 5 /nobreak (PID 2004)
  └── C:\Windows\System32\svctrl64.exe (PID 2564)
```

**Observations:**
1. **Self-deletion**: Spawns `cmd.exe` to delete itself after a 5-second delay
2. **Drops `svctrl64.exe`**: The persistent miner executable in `C:\Windows\System32\`
3. **Drops `wlogz.dat`**: Encrypted configuration file in `C:\Windows\System32\wsvcz\`

### 4.2 CAPE Sandbox — svctrl64.exe (The Miner Service)

The CAPE sandbox captured the **full malicious behavior** of `svctrl64.exe`:

```
svctrl64.exe (PID 3716)
  └── services.exe (PID 680)
        ├── svchost.exe -k DcomLaunch (PID 5844)
        │     ├── powershell.exe -Command "Add-MpPreference -ExclusionPath 'E:\'"
        │     ├── powershell.exe -Command "Add-MpPreference -ExclusionPath 'c:\windows\system32'"
        │     └── powershell.exe -Command "Add-MpPreference -ExclusionPath 'D:\'"
        └── [multiple svchost.exe instances]
```

**Critical behaviors observed:**

1. **Windows Defender Exclusion** — Adds exclusion paths via PowerShell for `C:\Windows\System32`, `D:\`, and `E:\` drives, preventing Defender from scanning the malware installation directory

2. **Service Persistence** — Registers as a Windows service under the DcomLaunch service group:
   ```
   HKLM\SYSTEM\CurrentControlSet\Services\u760237\Parameters\ServiceDll
       = C:\Windows\System32\u760237.dll
   ```
   The service name is **randomized** (different in each execution: `u760237`, `u350351`), making static detection harder.

3. **Hiberboot Disable** — Registry modification to prevent fast startup:
   ```
   HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power\HiberbootEnabled = 0
   ```

### 4.3 Mutex for Single Instance

```
decrypted_payload{ef18cb0d-aaa5-40e3-ba71-31d5ca7370fd}
```

This GUID-based mutex ensures only one instance of the miner runs at a time, preventing resource contention that might alert the user.

---

## 5. MITRE ATT&CK Mapping

### Original DLL (`idll.dll`)

| Tactic | Technique | Evidence |
|--------|-----------|----------|
| Defense Evasion | **T1027** Obfuscated Files | XOR cipher, AES-256-CBC encryption |
| Defense Evasion | **T1027.005** Indicator Removal | Obfuscated stackstrings |
| Defense Evasion | **T1497.001** Anti-VM System Checks | Xen anti-VM strings |
| Defense Evasion | **T1497** Virtualization/Sandbox Evasion | Sleep delays, parameter check |

### Decrypted Payload & svctrl64.exe

| Tactic | Technique | Evidence |
|--------|-----------|----------|
| Defense Evasion | **T1027** Obfuscated Files | RC4 PRGA encryption, XOR encoding, Base64 |
| Defense Evasion | **T1027.005** Indicator Removal | Obfuscated stackstrings |
| Defense Evasion | **T1497.001** Anti-VM | Anti-VM string references |
| Persistence | **T1543.003** Windows Service | Creates and starts service, registers ServiceDll |
| Persistence | **T1569.002** Service Execution | Service creation via DcomLaunch |
| Execution | **T1129** Shared Modules | Runtime function linking, PE header parsing |
| Discovery | **T1082** System Info | Environment variable queries |
| Discovery | **T1083** File Discovery | File enumeration, file size queries |
| Discovery | **T1614** System Location | Geographical location detection |

---

## 6. The Search for the Wallet Address

### 6.1 Why Standard String Extraction Failed

The Monero wallet address is not stored in plaintext anywhere in the binary. The following approaches were tried:

| Approach | Method | Result |
|----------|--------|--------|
| `strings` + regex | Search for `1xxxx`, `3xxxx`, `bc1xxx`, `4xxxx` (Monero) | No wallet found |
| Wide string search | `strings -el` with mining keywords | Found config keys but no wallet |
| Single-byte XOR brute-force | Try all 256 keys on full binary, search for `stratum+tcp://` | No matches |
| RC4 with adjacent keys | Try RC4 with 8/16/32-byte keys from nearby .data offsets | No config found |
| JSON pattern search | Look for `{` + `pool`/`url`/`wallet` in .rdata | No plaintext JSON |

### 6.2 The RC4 Encryption Layer

CAPA analysis confirmed the presence of **RC4 PRGA** (Pseudo-Random Generation Algorithm) in the miner:

```
T1027 [INFO] encrypt data using RC4 PRGA
T1027 [INFO] reference Base64 string
T1027.005 [INFO] contain obfuscated stackstrings
```

The config construction in the dropper uses **nlohmann::json** (confirmed by C++ RTTI strings in `.data`):

```python
# Evidence of nlohmann::json in .data section:
".?AVtype_error@detail@json_abi_v3_12_0@nlohmann@@"
".?AVout_of_range@detail@json_abi_v3_12_0@nlohmann@@"
".?AVparse_error@detail@json_abi_v3_12_0@nlohmann@@"
```

And **asio** networking library:
```python
".?AV?$typeid_wrapper@Vconfig_service@asio@@@detail@asio@@"
".?AV?$typeid_wrapper@Vresolver_thread_pool@detail@asio@@@detail@asio@@"
```

### 6.3 The `wlogz.dat` Config File

The sandbox captured the dropped `wlogz.dat`:

| Property | Value |
|----------|-------|
| Path | `C:\Windows\System32\wsvcz\wlogz.dat` |
| Size | **32 bytes** |
| SHA256 | `d69c801816d056c78adb6d20777edd87b02b32b3e2b87fab2f457ba54617bf60` |
| VT Detection | 0/76 (clean — too small for signatures) |

At only 32 bytes, `wlogz.dat` cannot contain a full mining config. It is likely an **RC4 key** or **database connection string** used to decrypt the full config received from the C2 server.

### 6.4 The Wide String Evidence

Critical wide strings found in `embedded_01.bin` that reveal the malware's behavior:

```python
# Config-related strings
"wlogz.dat"                          # Config filename
"wsvcz"                              # Config directory name
"Config init error: "                # Config loading error
"DB error while updating config settings: "  # Database-backed config

# Installation strings
"Infector install error: "           # Dropper component
"CPU install error: "                # CPU miner installation
"GPU install error: "                # GPU miner installation
"CURL global init error: "           # HTTP client initialization

# Execution strings
" && timeout /t 5 /nobreak && sc.exe start "  # Service start command
"timeout /t 10 /nobreak && sc.exe stop "      # Service stop command
"C:\Windows\System32\"               # Installation path
".dat"                               # Data file extension
".exe"                               # Executable extension

# Anti-detection strings
"powershell.exe -Command \"Add-MpPreference -ExclusionPath 'c:\\windows\\system32'\""

# Registry strings
"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\LogonUI"
"SOFTWARE\\Microsoft\\Cryptography"
```

---

## 7. ASEC Intelligence Correlation — Why This Is PrintMiner

### 7.1 AhnLab ASEC Report Match

In February 2025 and November 2025, [AhnLab ASEC published reports](https://asec.ahnlab.com/en/91415/) on a CoinMiner malware spread via USB in South Korea. In July 2025, Mandiant also released a report categorizing the malware as **DIRTYBULK** and **CUTFAIL**.

Our sample matches the ASEC report in **every significant detail**:

| Characteristic | Our Sample | ASEC Report | Match |
|---------------|------------|-------------|-------|
| **Infection vector** | USB / DLL side-loading | USB / DLL side-loading | **YES** |
| **DLL name** | `idll.dll` / `printui.dll` | `printui.dll` | **YES** |
| **Export name** | `IdllEntry` | Loaded via legitimate exe | **YES** |
| **Dropped file** | `svctrl64.exe` | `svctrl64.exe` | **EXACT** |
| **Config file** | `wlogz.dat` in `wsvcz\` | `wlogz.dat` in `wsvcz\` | **EXACT** |
| **Service registration** | DcomLaunch service group | DcomLaunch service group | **EXACT** |
| **Randomized service name** | `u760237`, `u350351` | `u826437` (same pattern: `u` + 6 digits) | **YES** |
| **Service DLL** | `u760237.dll` in System32 | `u826437.dll` in System32 | **YES** |
| **Defender exclusion** | `Add-MpPreference -ExclusionPath 'c:\windows\system32'` | Same PowerShell command | **EXACT** |
| **Hiberboot disabled** | `HiberbootEnabled = 0` | Same registry modification | **YES** |
| **Self-deletion** | `cmd.exe /c timeout /t 5 /nobreak && del /q` | Same technique | **YES** |
| **XMRig usage** | RC4-encrypted config, `--tls` | Same XMRig configuration | **YES** |
| **Process monitoring evasion** | Terminates when monitoring tools detected | Checks for Process Explorer, TaskMgr, etc. | **YES** |
| **PostgreSQL C2** | `DB error` strings, database config | PostgreSQL database for C2 | **YES** |
| **USB worm** | `spreader` tag on VT | Creates `USB Drive.lnk`, moves files | **YES** |

### 7.2 The Code Proves the Connection

The `u` prefix + 6-digit naming convention for both the `.dat` dropper file and the service DLL is a **unique fingerprint** of this campaign:

```
Our sample:   u297528.dat → u760237.dll / u350351.dll
ASEC report:  u211553.dat → u826437.dll
```

This naming convention is generated by the USB worm component and passed to the installer, proving the samples are from the **same toolset and campaign**.

### 7.3 Mining Pool Configuration (from ASEC)

The ASEC report captured the XMRig execution parameters from a live infection:

```
-o r2.hashpoolpx[.]net:443 --tls --tls-fingerprint=AFE39FE58C921511972C90ACF72937F84AD96BA4C732ECF6501540E568620C2F --dns-ttl=3600 --max-cpu-usage=50
```

| Parameter | Value | Purpose |
|-----------|-------|---------|
| `-o` | `r2.hashpoolpx[.]net:443` | **Mining pool: HashPool** (TLS, port 443) |
| `--tls` | (flag) | TLS encryption for mining traffic |
| `--tls-fingerprint` | `AFE39FE5...620C2F` | TLS certificate pinning (anti-MITM) |
| `--dns-ttl` | `3600` | DNS cache for 1 hour |
| `--max-cpu-usage` | `50` | **Limit CPU to 50%** (avoid user detection) |

---

## 8. C2 Infrastructure and IOCs

### 8.1 Network IOCs (from ASEC + VT correlation)

| IOC | Value | Purpose |
|-----|-------|---------|
| **C2 Domain** | `umnsrx[.]net` | Command & control server |
| **C2 IP** | `2[.]58[.]56[.]13` | C2 server IP address |
| **C2 Config URL** | `http://2.58.56.13/inf.dat` | Miner config download |
| **C2 XMRig URL** | `http://2.58.56.13/utl/xmr.dat` | XMRig binary download |
| **C2 Driver URL** | `http://2.58.56.13/utl/xmrsys.dat` | XMRig kernel driver |
| **Mining Pool** | `r2[.]hashpoolpx[.]net:443` | HashPool mining pool |
| **TLS Fingerprint** | `AFE39FE58C921511972C90ACF72937F84AD96BA4C732ECF6501540E568620C2F` | TLS cert pinning |

### 8.2 File IOCs

| File | MD5 | SHA256 | Detection |
|------|-----|--------|-----------|
| `u297528.dat` (idll.dll) | `dbd8dbecaa80795c135137d69921fdba` | `e60ab99da105ee27ee09ea64ed8eb46d8edc92ee37f039dbc3e2bb9f587a33ba` | 55/71 |
| `decrypted_payload.exe` | `e10a9bb09acb415e5dc8654b8593a45c` | `d59e83b0be737896dec8b91c7a52f87e16f83e911af52826b98481b5c50f32b2` | 38/71 |
| `embedded_00.bin` (miner) | `ce527e9ec2dd83c0565796f5420ce4e4` | `5543d3b826de134bc47212be344f0c7def51704516d40f611b406c6e98baaa3a` | 8/71 |
| `embedded_01.bin` (dropper) | `00615f1a46899c659ad9582f43489f9f` | `2be97a48015544620fe1e3bb69b130a24ddbb31f9719173868579df489e9356c` | 54/70 |
| `svctrl64.exe` (dropped) | `9bfa7a2991a8b62b5ef12a920b220e1e` | `ec860277d21159deb084b7849149a3700d98dc42d7d69e2e3acceed6dbe3158e` | 57/75 |
| `wlogz.dat` (config) | `9de2bb040c501effa18a630ddf3db103` | `d69c801816d056c78adb6d20777edd87b02b32b3e2b87fab2f457ba54617bf60` | 0/76 |

### 8.3 Behavioral IOCs

| IOC | Value |
|-----|-------|
| Mutex | `decrypted_payload{ef18cb0d-aaa5-40e3-ba71-31d5ca7370fd}` |
| Dropped path | `C:\Windows\System32\svctrl64.exe` |
| Dropped path | `C:\Windows\System32\wsvcz\wlogz.dat` |
| Service DLL | `C:\Windows\System32\uXXXXXX.dll` (randomized) |
| Defender exclusion | `Add-MpPreference -ExclusionPath 'c:\windows\system32'` |
| Self-delete command | `cmd.exe /c timeout /t 5 /nobreak && del /q <path>` |
| Hiberboot disabled | `HKLM\...\Power\HiberbootEnabled = 0` |

---

## 9. Why the Wallet Is Not in the Binary

### 9.1 The Config Retrieval Flow

Based on the combined evidence from static analysis, sandbox results, and ASEC intelligence, the wallet address retrieval works as follows:

```
1. svctrl64.exe starts as a Windows service (DcomLaunch group)

2. Connects to C2 at 2.58.56.13 / umnsrx.net
   Uses PostgreSQL database protocol (confirmed by "DB init error" string)
   
3. Sends system fingerprint (CPU, GPU, locale, geo)
   
4. Receives encrypted config containing:
   - Monero wallet address (XMR: 4[1-9A-HJ-NP-Za-km-z]{94})
   - Mining pool URL and port
   - TLS fingerprint for cert pinning
   - CPU usage limit
   - Process blacklist (monitoring tools, games)
   
5. Writes config to C:\Windows\System32\wsvcz\wlogz.dat (RC4 encrypted)
   wlogz.dat is only 32 bytes → likely an RC4 key or DB connection hash
   
6. Downloads XMRig from C2 (http://2.58.56.13/utl/xmr.dat)
   Also downloads WinRing0x64.sys kernel driver (xmrsys.dat)
   
7. Executes XMRig with decrypted config parameters:
   -o r2.hashpoolpx.net:443 --tls --tls-fingerprint=... --max-cpu-usage=50
   --user <WALLET_ADDRESS>
```

### 9.2 How to Extract the Wallet

Since the wallet is fetched from the C2 at runtime:

1. **Internet-connected sandbox** — Run `svctrl64.exe` with network access, capture the PostgreSQL C2 response
2. **Memory forensics** — After miner is running, dump `svctrl64.exe` process memory and search for Monero address pattern: `4[1-9A-HJ-NP-Za-km-z]{94}`
3. **Network interception** — TLS-pinned connection to HashPool reveals the wallet in the stratum `login` field
4. **C2 seizure** — If the C2 server at `2.58.56.13` is seized, the PostgreSQL database would contain all wallet addresses

---

## 10. Complete Attack Chain (Full)

```
1. USB device inserted into Windows host
     |
2. User clicks "USB Drive.lnk" shortcut
     |
3. VBS script → BAT script executes
     |
4. BAT creates "C:\Windows \System32\" (trailing space)
   Copies u297528.dat as "printui.dll" / "idll.dll"
   Copies legitimate printui.exe to same folder
     |
5. Legitimate EXE loads idll.dll via DLL side-loading
     |
6. DllMain: DisableThreadLibraryCalls()
     |
7. IdllEntry called with param='1'
     |
8. PEB hash walking resolves ntdll.dll functions
   (seed=0xe7A1, multiplier=0x21, uppercase WCHAR)
     |
9. Syscall numbers extracted from ntdll stubs [+4 offset]
     |
10. Position-dependent XOR decodes substitution table
    formula: decoded[i] = (key ^ data[i]) ^ (0x3D*(i+1) & 0xFF)
     |
11. AES-256-CBC decrypts 6.81 MB payload
    Key: b1fa3fd02d8ec02302cf4ce7a46957f76eaaa7c5a73b3d2cb6bcb4a322593180
    IV:  815f73d17e0ab351296629a197d378a5
     |
12. Direct syscalls drop & execute decrypted payload
    NtCreateFile → NtWriteFile → NtCreateUserProcess
     |
13. Payload self-deletes (cmd.exe /c timeout /t 5 && del)
     |
14. Drops C:\Windows\System32\svctrl64.exe (miner service)
     |
15. Drops C:\Windows\System32\wsvcz\wlogz.dat (RC4-encrypted config)
     |
16. svctrl64.exe registers as Windows service (DcomLaunch)
    Service name: uXXXXXX (randomized 6 digits)
    ServiceDll: C:\Windows\System32\uXXXXXX.dll
     |
17. Adds Windows Defender exclusion via PowerShell
    Add-MpPreference -ExclusionPath 'c:\windows\system32'
     |
18. Disables Hiberboot (HiberbootEnabled = 0)
     |
19. Connects to C2 at 2.58.56.13 / umnsrx.net
    PostgreSQL database protocol
    Sends: CPU, GPU, locale, geo info
    Receives: wallet, pool URL, TLS fingerprint, config
     |
20. Downloads XMRig + WinRing0x64.sys from C2
     |
21. Executes XMRig with decrypted config:
    -o r2.hashpoolpx.net:443 --tls --tls-fingerprint=AFE39FE5...
    --max-cpu-usage=50 --user <MONERO_WALLET>
     |
22. Monero mining begins (50% CPU limit)
    Terminates if monitoring tools or games detected
     |
23. USB worm thread creates "USB Drive.lnk" on all removable drives
    Moves user files to hidden "sysvolume" folder
    Copies malware VBS/BAT/DAT to new USB devices
```

---

## 11. Anti-Detection Techniques Summary

| Technique | Implementation | Purpose |
|-----------|---------------|---------|
| **Hash-based API resolution** | PEB walking with custom hash (seed=0xe7A1) | Hide imports from static analysis |
| **Direct syscalls** | 6 stubs with dynamic syscall number resolution | Bypass EDR hooks on ntdll |
| **AES-256-CBC encryption** | Embedded payload encrypted in .data section | Hide the real payload |
| **Position-dependent XOR** | Arithmetic sequence constant: `(0x3D*(i+1)) & 0xFF` | Obfuscate substitution table |
| **RC4 config encryption** | Wallet/pool config encrypted with RC4 | Hide mining config |
| **Obfuscated stackstrings** | Config keys built at runtime | Evade string-based detection |
| **Self-deletion** | `cmd.exe /c timeout /t 5 && del /q` | Remove forensic evidence |
| **Windows Defender exclusion** | `Add-MpPreference -ExclusionPath` | Prevent AV scanning of install dir |
| **CPU throttling** | `--max-cpu-usage=50` | Avoid user noticing slowdown |
| **Process monitoring evasion** | Terminates when TaskMgr/ProcessExplorer running | Hide from user inspection |
| **Game detection** | Terminates when game processes running | Avoid performance complaints |
| **TLS certificate pinning** | `--tls-fingerprint=AFE39FE5...` | Prevent SSL inspection |
| **Service persistence** | DcomLaunch service with randomized name | Survive reboots, evade detection |
| **Hiberboot disable** | `HiberbootEnabled = 0` | Keep system running for mining |

---

## 12. YARA Detection Rules for Miner Components

```yara
rule printminer_dropper {
    meta:
        description = "Detects PrintMiner dropper (embedded_01.bin)"
        severity = "HIGH"
        reference = "https://asec.ahnlab.com/en/91415/"
    strings:
        $s1 = "wlogz.dat" wide
        $s2 = "wsvcz" wide
        $s3 = "CPU install error" wide
        $s4 = "GPU install error" wide
        $s5 = "Config init error" wide
        $s6 = "Infector install error" wide
        $s7 = "DB init error" wide
    condition:
        3 of them
}

rule printminer_service {
    meta:
        description = "Detects svctrl64.exe PrintMiner service component"
        severity = "HIGH"
    strings:
        $s1 = "Add-MpPreference" wide
        $s2 = "sc.exe start" wide
        $s3 = "sc.exe stop" wide
        $s4 = "DcomLaunch" wide
    condition:
        2 of them and filesize > 5MB
}

rule printminer_config {
    meta:
        description = "Detects PrintMiner wlogz.dat config file"
        severity = "MEDIUM"
    condition:
        filesize == 32
}
```

---

## 13. Tools Used

| Tool | Purpose |
|------|---------|
| `pefile` (Python) | PE parsing, section extraction, embedded PE identification |
| `VirusTotal v3 API` | File submission, detection lookup, behavioral reports |
| `pycryptodome` | AES-256-CBC decryption of payload |
| `VT Jujubox` | Dynamic behavioral analysis of decrypted payload |
| `CAPE Sandbox` (via VT) | Behavioral analysis of svctrl64.exe |
| `CAPA` (via VT) | Static capability analysis, MITRE ATT&CK mapping |
| `YARA 4.5.5` | Detection rule creation and testing |
| `strings` / regex | String extraction and pattern matching |
| `requests` (Python) | VirusTotal API interaction |

---

## 14. References

1. AhnLab ASEC, "CoinMiner Malware Being Continuously Distributed via USB" (Nov 2025): https://asec.ahnlab.com/en/91415/
2. AhnLab ASEC, "CoinMiner Malware Distributed via USB" (Feb 2025): https://asec.ahnlab.com/en/86221/
3. Mandiant, DIRTYBULK / CUTFAIL report (Jul 2025)
4. VirusTotal File Report — u297528.dat: https://www.virustotal.com/gui/file/e60ab99da105ee27ee09ea64ed8eb46d8edc92ee37f039dbc3e2bb9f587a33ba
5. VirusTotal File Report — decrypted_payload.exe: https://www.virustotal.com/gui/file/d59e83b0be737896dec8b91c7a52f87e16f83e911af52826b98481b5c50f32b2
