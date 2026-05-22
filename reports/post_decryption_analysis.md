# Post-Decryption Analysis Report: idll.dll Bitcoin Miner Dropper

## Threat Classification

| Property | Value |
|----------|-------|
| **Family** | **Tedy** / GenericFCA Bitcoin Miner Dropper |
| **Type** | Trojan / Cryptocurrency Miner |
| **VT Suggested Label** | `trojan.tedy/misc` |
| **Primary Category** | Trojan (18 engines), Miner (7 engines) |
| **Delivery Vector** | Infected USB / DLL side-loading |

---

## VirusTotal Detection Results

### Original DLL (`u297528.dat` / `idll.dll`)

| Metric | Value |
|--------|-------|
| **Detection** | **55/71 (77.5%)** |
| SHA256 | `e60ab99da105ee27ee09ea64ed8eb46d8edc92ee37f039dbc3e2bb9f587a33ba` |
| VT Link | [View on VT](https://www.virustotal.com/gui/file/e60ab99da105ee27ee09ea64ed8eb46d8edc92ee37f039dbc3e2bb9f587a33ba) |
| Tags | `detect-debug-environment`, `long-sleeps`, `pedll`, `spreader`, `64bits` |
| Classification | `trojan.genericfca/agentb` |

**Top Detections:**
- Bkav: `W32.Malware.9F35BFE9`
- MicroWorld-eScan: `Trojan.GenericFCA.299`
- Malwarebytes: `Trojan.MalPack`
- Zillya: `Trojan.Agent.Win64.168174`
- Sangfor: `Trojan.Win64.Agent.Vvta`
- CrowdStrike: `win/malicious_confidence_100% (D)`

### Decrypted Payload (`decrypted_payload.exe`)

| Metric | Value |
|--------|-------|
| **Detection** | **38/71 (53.5%)** |
| SHA256 | `d59e83b0be737896dec8b91c7a52f87e16f83e911af52826b98481b5c50f32b2` |
| VT Link | [View on VT](https://www.virustotal.com/gui/file/d59e83b0be737896dec8b91c7a52f87e16f83e911af52826b98481b5c50f32b2) |
| Tags | `peexe`, `overlay`, `64bits`, `persistence` |
| Classification | `trojan.tedy/misc` |

**Top Detections:**
- CAT-QuickHeal: **`Trojan.Coinminer.S38826036`**
- Zillya: **`Trojan.BitCoinMiner.Win32.1739`**
- Antiy-AVL: **`Trojan[Miner]/Win32.BitCoinMiner`**
- Gridinsoft: **`Trojan.Win64.CoinMiner.dd!s1`**
- Microsoft: **`Trojan:Win32/Wacatac.B!ml`**
- CrowdStrike: `win/malicious_confidence_100% (D)`

### Embedded PE #0 (`embedded_00.bin`) — Miner Component

| Metric | Value |
|--------|-------|
| **Detection** | **8/71 (11.3%)** |
| SHA256 | `5543d3b826de134bc47212be344f0c7def51704516d40f611b406c6e98baaa3a` |
| Size | 235,968 bytes (230 KB) |
| Machine | x86-64 |
| VT Link | [View on VT](https://www.virustotal.com/gui/file/5543d3b826de134bc47212be344f0c7def51704516d40f611b406c6e98baaa3a) |

**Key detections:** `Trojan.BitCoinMiner.Win32.1740` (Zillya), `Trojan[Miner]/Win32.BitCoinMiner` (Antiy-AVL), `Trojan.Win64.CoinMiner.dd!s1` (Gridinsoft)

### Embedded PE #1 (`embedded_01.bin`) — Main Dropper

| Metric | Value |
|--------|-------|
| **Detection** | **54/70 (77.1%)** |
| SHA256 | `2be97a48015544620fe1e3bb69b130a24ddbb31f9719173868579df489e9356c` |
| Size | 6,620,160 bytes (6.3 MB) |
| Machine | x86-64 |
| Imports | WS2_32.dll (48 funcs), WTSAPI32.dll, NETAPI32.dll |
| VT Link | [View on VT](https://www.virustotal.com/gui/file/2be97a48015544620fe1e3bb69b130a24ddbb31f9719173868579df489e9356c) |

**Key detections:** `Trojan.BitcoinMiner` (CAT-QuickHeal), `BehavesLike.Win64.Dropper.vh` (Skyhigh), `Misc.Riskware.BitCoinMiner` (ALYac)

---

## Sandbox Behavioral Analysis

### Source: VirusTotal Jujubox (Dynamic Analysis)

When the decrypted payload is executed, the following behavior is observed:

#### Process Execution Chain

```
decrypted_payload.exe (PID 2996)
  └── cmd.exe /c timeout /t 5 /nobreak && del /q C:\Users\<USER>\Downloads\decrypted_payload.exe (PID 648)
        └── timeout /t 5 /nobreak (PID 2004)
  └── C:\Windows\System32\svctrl64.exe (PID 2564)
```

**Key behavioral observations:**
1. **Self-deletion**: The payload immediately spawns `cmd.exe` to delete itself after a 5-second delay — a classic anti-forensic technique
2. **Drops `svctrl64.exe`**: Installs a service controller executable in `C:\Windows\System32\` — this is the persistent Bitcoin miner
3. **Service installation**: The `svctrl64.exe` name mimics a legitimate Windows service controller

#### Dropped Files

| Path | Purpose |
|------|---------|
| `C:\Windows\System32\svctrl64.exe` | **Bitcoin miner service executable** |
| `C:\Windows\System32\wsvcz\wlogz.dat` | **Miner configuration/log data** |

#### Created Mutexes

| Mutex | Purpose |
|-------|---------|
| `decrypted_payload{ef18cb0d-aaa5-40e3-ba71-31d5ca7370fd}` | **Single-instance lock** — prevents multiple miner instances |

### Source: VirusTotal C2AE (Original DLL Sandbox)

When the original `idll.dll` is loaded via `rundll32.exe`:

```
SANDBOX_DLL_LOADER_AMD64 %TEMP%\B2X7XPG6VZAIINXY.dll %WORKDIR% 483
  └── rundll32.exe %TEMP%\B2X7XPG6VZAIINXY.dll,IdllEntry
```

This confirms the DLL side-loading attack vector: the DLL is loaded via `rundll32.exe` with the export `IdllEntry` called.

---

## MITRE ATT&CK Mapping

### Original DLL (`idll.dll`) — CAPA Analysis

| Tactic | Technique | Description |
|--------|-----------|-------------|
| **Defense Evasion** | T1027 | Obfuscated Files or Information — encode data using XOR |
| **Defense Evasion** | T1027 | encrypt data using AES |
| **Defense Evasion** | T1027 | reference AES constants |
| **Defense Evasion** | T1027.005 | Indicator Removal from Tools — obfuscated stackstrings |
| **Defense Evasion** | T1027 | encode data using ADD XOR SUB operations |
| **Defense Evasion** | T1497.001 | Virtualization/Sandbox Evasion: System Checks — anti-VM strings targeting Xen |
| **Defense Evasion** | T1497 | Virtualization/Sandbox Evasion |

### Decrypted Payload — CAPA Analysis

| Tactic | Technique | Description |
|--------|-----------|-------------|
| **Defense Evasion** | T1027 | reference Base64 string |
| **Defense Evasion** | T1027 | encrypt data using RC4 PRGA |
| **Defense Evasion** | T1027.005 | contain obfuscated stackstrings |
| **Defense Evasion** | T1497.001 | reference anti-VM strings |
| **Discovery** | T1082 | query environment variable |
| **Discovery** | T1083 | enumerate files on Windows |
| **Discovery** | T1614 | get geographical location |
| **Execution** | T1129 | link function at runtime on Windows |
| **Execution** | T1129 | parse PE header |
| **Persistence** | — | Writes to System32 (service installation) |

---

## Network Indicators

The embedded PE #1 imports **WS2_32.dll** with 48 socket functions — extensive networking capability for mining pool communication.

### Observed String References

| Indicator | Context |
|-----------|---------|
| `https://github.com/dot-asm` | Reference to assembler library (used in miner optimization) |
| `https://curl.se/docs/alt-svc.html` | libcurl documentation (HTTP/HTTPS client) |
| `https://curl.se/docs/hsts.html` | HSTS support in libcurl |
| `https://curl.se/docs/http-cookies.html` | Cookie handling in libcurl |
| `github.com` | Domain reference |
| `example.com` | Test/placeholder domain |

### Network Capabilities (from WS2_32.dll imports)

The 48 imported socket functions indicate the miner component supports:
- Full TCP/UDP socket creation and communication
- DNS resolution for mining pool endpoints
- HTTP/HTTPS connections (via embedded libcurl)
- Long-lived persistent connections (mining pool stratum protocol)

> **Note:** Mining pool addresses and wallet IDs are likely **encrypted or downloaded at runtime** (RC4 encryption observed by CAPA), which is why they don't appear as plaintext in the binary.

---

## Complete Attack Chain (Updated with Behavioral Data)

```
1. USB device inserted into Windows host
     |
2. Legitimate application loads idll.dll via DLL side-loading
     |
3. DllMain: DisableThreadLibraryCalls() — minimal footprint
     |
4. IdllEntry called with param='1'
     |
5. PEB hash walking resolves ntdll.dll functions
     |
6. Syscall numbers extracted from ntdll stubs [+4 offset]
     |
7. Position-dependent XOR decodes substitution table
     |
8. AES-256-CBC decrypts 6.81 MB payload from .data section
     |
9. Direct syscalls: NtCreateFile + NtWriteFile drop payload to disk
     |
10. NtCreateUserProcess executes dropped payload
     |
11. Payload self-deletes via cmd.exe (5s delay)
     |
12. Drops C:\Windows\System32\svctrl64.exe (Bitcoin miner)
     |
13. Creates C:\Windows\System32\wsvcz\wlogz.dat (config)
     |
14. Creates mutex: decrypted_payload{ef18cb0d-...}
     |
15. svctrl64.exe connects to mining pool via stratum protocol
     |
16. Cryptocurrency mining begins (persistent via System32 install)
```

---

## Updated IOCs

### File IOCs

| File | MD5 | SHA256 | Detection |
|------|-----|--------|-----------|
| `u297528.dat` (idll.dll) | `dbd8dbecaa80795c135137d69921fdba` | `e60ab99da105ee27ee09ea64ed8eb46d8edc92ee37f039dbc3e2bb9f587a33ba` | 55/71 (77.5%) |
| `decrypted_payload.exe` | `e10a9bb09acb415e5dc8654b8593a45c` | `d59e83b0be737896dec8b91c7a52f87e16f83e911af52826b98481b5c50f32b2` | 38/71 (53.5%) |
| `embedded_00.bin` (miner) | `ce527e9ec2dd83c0565796f5420ce4e4` | `5543d3b826de134bc47212be344f0c7def51704516d40f611b406c6e98baaa3a` | 8/71 (11.3%) |
| `embedded_01.bin` (dropper) | `00615f1a46899c659ad9582f43489f9f` | `2be97a48015544620fe1e3bb69b130a24ddbb31f9719173868579df489e9356c` | 54/70 (77.1%) |
| `svctrl64.exe` (dropped) | Unknown | Unknown | Bitcoin miner service |
| `wlogz.dat` (dropped config) | Unknown | Unknown | Miner configuration |

### Behavioral IOCs

| IOC | Value |
|-----|-------|
| Mutex | `decrypted_payload{ef18cb0d-aaa5-40e3-ba71-31d5ca7370fd}` |
| Dropped path | `C:\Windows\System32\svctrl64.exe` |
| Dropped path | `C:\Windows\System32\wsvcz\wlogz.dat` |
| Self-delete cmd | `cmd.exe /c timeout /t 5 /nobreak && del /q <path>` |
| Export called | `IdllEntry` via `rundll32.exe` |

### Crypto IOCs

| IOC | Value |
|-----|-------|
| AES-256 Key | `b1fa3fd02d8ec02302cf4ce7a46957f76eaaa7c5a73b3d2cb6bcb4a322593180` |
| AES IV | `815f73d17e0ab351296629a197d378a5` |
| XOR Seed | `0x3D` (constant formula: `(0x3D * (i+1)) & 0xFF`) |
| API Hash Seed | `0xe7A1` |

---

## CAPE Sandbox Note

The `celyrin/cape` Docker container could not be started because CAPE requires **nested virtualization** (KVM/VirtualBox) to run its Windows guest VM. This environment (Kali Linux without hardware VM passthrough) does not support this requirement.

**Alternative approaches for local dynamic analysis:**
1. Use a Windows VM with Sysinternals tools (Process Monitor, TCPView, Autoruns)
2. Use ANY.RUN free sandbox (web-based, no local VM needed)
3. Use Joe Sandbox cloud (free tier available)
4. Set up CAPE on a host with hardware virtualization support

The VirusTotal Jujubox and C2AE sandbox results above provide equivalent behavioral data.

---

## Artifacts Generated

| File | Location | Description |
|------|----------|-------------|
| `embedded_00.bin` | `findings/data/embedded_pes/` | Bitcoin miner component (230 KB) |
| `embedded_01.bin` | `findings/data/embedded_pes/` | Main dropper with WS2_32 networking (6.3 MB) |
| `embedded_analysis.json` | `findings/data/` | Full extraction metadata + network indicators |
| `virustotal_results.json` | `findings/data/` | VT detection results for all 4 files |
| `mitre_original_dll.json` | `findings/data/` | MITRE ATT&CK mapping for original DLL |
| `mitre_decrypted_payload.json` | `findings/data/` | MITRE ATT&CK mapping for decrypted payload |
