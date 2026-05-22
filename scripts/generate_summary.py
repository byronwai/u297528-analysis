#!/usr/bin/env python3
"""
Final Summary Checkpoint Generator for u297528.dat Analysis
"""

import json, os, hashlib
from datetime import datetime, timezone

SAMPLE = "/home/kali/Downloads/sandbox/u297528.dat"
OUT_DIR = "/home/kali/Downloads/sandbox/findings"

def main():
    with open(SAMPLE, "rb") as f:
        sample_data = f.read()
    
    md5 = hashlib.md5(sample_data).hexdigest()
    sha256 = hashlib.sha256(sample_data).hexdigest()
    
    # Load all analysis results
    results = {
        "analysis_metadata": {
            "sample_file": os.path.basename(SAMPLE),
            "sample_size": len(sample_data),
            "sample_md5": md5,
            "sample_sha256": sha256,
            "analysis_date": datetime.now(timezone.utc).isoformat(),
            "tools_used": ["radare2", "objdump", "strings", "python3", "xxd"],
            "analyst_notes": "Blog reference (imaginary-paw-91f.notion.site Infected USB) could not be fetched due to JavaScript requirement",
        },
        "key_findings": {
            "malware_type": "DLL Side-Loading Loader (USB drop vector)",
            "dll_name": "idll.dll",
            "export_function": "IdllEntry",
            "compiler": "MSVC v14.00 (Visual Studio 2015/2017)",
            "pe_timestamp": "2026-01-29 05:42:10 UTC",
            "file_size": "12.6 MB",
            "key_evasion_techniques": [
                "1. Hash-based API resolution via PEB walking (algorithm: hash=0xe7A1, mul=0x21)",
                "2. Direct syscall execution (bypasses EDR user-mode API hooks)",
                "3. Minimal import table (3 KERNEL32.dll functions only)",
                "4. Custom position-dependent XOR cipher for payload decryption",
                "5. Malformed delay import directory (anti-analysis)",
                "6. ~12.5MB encrypted payload in .data section (no embedded PE signatures)",
            ],
            "resolved_api_hashes": {
                "0x695b8977": "NtCreateFile",
                "0x4d799fce": "NtWriteFile",
                "0x844c5e59": "NtClose",
                "0x40583309": "NTDLL.DLL (uppercase Unicode hash)",
            },
            "malware_capabilities": [
                "File creation/writing (NtCreateFile, NtWriteFile) - drops payload to disk",
                "Process spawning (NtCreateUserProcess syscall) - executes dropped file",
                "DLL loading (LdrLoadDll) - loads additional modules dynamically",
                "Object waiting (NtWaitForSingleObject) - monitors spawned process",
                "Sleep/delay (NtDelayExecution) - timing control",
                "Direct syscalls for all Nt* operations - bypasses EDR hooks",
            ],
            "payload_analysis": {
                "data_section_size": "12.5 MB",
                "low_entropy_region": "~5.7 MB (0x00/0xFF pattern - likely encoded lookup table)",
                "high_entropy_region": "~7 MB (entropy 7.07-7.31 - encrypted payload)",
                "encryption_type": "Multi-layer: position-dependent XOR + likely AES-CTR/ChaCha20",
                "embedded_pe_found": False,
                "decryption_status": "Requires runtime emulation of IdllEntry to fully decrypt",
            },
            "execution_flow": [
                "1. DllMain: minimal - calls DisableThreadLibraryCalls, returns TRUE",
                "2. IdllEntry: checks parameter byte == '1' (0x31)",
                "3. Resolves ntdll.dll and another module via hash-based PEB walking",
                "4. Extracts syscall numbers from ntdll stubs (byte at offset +4)",
                "5. Builds substitution/decode table on stack (~300 word values)",
                "6. Calls position-dependent XOR decryption on substitution table",
                "7. Uses decoded table + direct syscalls to create file, write payload, spawn process",
            ],
            "iocs": {
                "dll_name": "idll.dll",
                "export_name": "IdllEntry",
                "pe_timestamp_hex": "0x697b3982",
                "pe_timestamp_date": "2026-01-29T05:42:10",
                "md5": md5,
                "sha256": sha256,
                "api_hash_seed": "0xe7A1",
                "api_hash_multiplier": "0x21",
                "syscall_stub_range": "0x180003f30-0x180003f6c",
                "syscall_number_storage": "0x180c51530-0x180c51544",
                "xor_decrypt_function": "0x180001a10",
                "data_section_entropy_range": "7.07-7.31",
            },
        },
        "generated_files": {
            "pe_analysis": "findings/pe_analysis.json",
            "analysis_report": "findings/analysis_report.txt",
            "decryption_analysis": "findings/decryption_analysis.json",
            "decryption_report": "findings/decryption_report.txt",
            "encrypted_payload_sample": "findings/encrypted_payload.bin",
            "hash_resolution": "findings/hash_resolution.json",
            "hash_resolution_report": "findings/hash_resolution_report.txt",
            "pe_analysis_script": "findings/pe_analysis.py",
            "decrypt_script": "findings/decrypt_payload.py",
            "hash_resolver_script": "findings/hash_resolver.py",
        },
        "next_steps": {
            "recommended_actions": [
                "1. Install Ghidra (apt install ghidra) for full decompilation of all functions",
                "2. Submit to VirusTotal/Joe Sandbox for automated behavioral analysis",
                "3. Emulate IdllEntry in a controlled Windows x64 sandbox to observe decryption",
                "4. Use CAPE sandbox (cape.io) for detailed malware behavior capture",
                "5. Cross-reference with known malware families using YARA rules",
                "6. Extract the full substitution table from IdllEntry for offline decryption",
                "7. Try to resolve remaining hash values using a full ntdll export database",
            ],
            "additional_tools_needed": [
                "Ghidra - for full decompilation (apt install ghidra)",
                "CAPE Sandbox - for behavioral analysis (Docker: cape/sandbox)",
                "YARA - for rule-based detection (apt install yara)",
                "pefile - Python library for deeper PE analysis (pip3 install pefile)",
                "Volatility - for memory forensics if sample was executed",
            ],
        },
    }
    
    out_file = os.path.join(OUT_DIR, "summary_checkpoint.json")
    with open(out_file, "w") as f:
        json.dump(results, f, indent=2)
    
    # Also write a concise human-readable summary
    summary_file = os.path.join(OUT_DIR, "SUMMARY.txt")
    with open(summary_file, "w") as f:
        f.write("=" * 70 + "\n")
        f.write("  FINAL ANALYSIS SUMMARY CHECKPOINT\n")
        f.write("  File: u297528.dat (idll.dll)\n")
        f.write("  Date: " + datetime.now().isoformat() + "\n")
        f.write("=" * 70 + "\n\n")
        
        fm = results["analysis_metadata"]
        f.write("FILE METADATA\n")
        f.write(f"  File: {fm['sample_file']}\n")
        f.write(f"  Size: {fm['sample_size']} bytes ({fm['sample_size']/1024/1024:.2f} MB)\n")
        f.write(f"  MD5:  {fm['sample_md5']}\n")
        f.write(f"  SHA256: {fm['sample_sha256']}\n\n")
        
        kf = results["key_findings"]
        f.write("MALWARE TYPE\n")
        f.write(f"  {kf['malware_type']}\n\n")
        
        f.write("KEY EVASION TECHNIQUES\n")
        for t in kf["key_evasion_techniques"]:
            f.write(f"  {t}\n")
        f.write("\n")
        
        f.write("RESOLVED API HASHES\n")
        for h, name in kf["resolved_api_hashes"].items():
            f.write(f"  0x{int(h, 16) if isinstance(h, str) else h:x} -> {name}\n")
        f.write("\n")
        
        f.write("MALWARE CAPABILITIES\n")
        for c in kf["malware_capabilities"]:
            f.write(f"  {c}\n")
        f.write("\n")
        
        f.write("PAYLOAD ANALYSIS\n")
        pa = kf["payload_analysis"]
        for k, v in pa.items():
            f.write(f"  {k}: {v}\n")
        f.write("\n")
        
        f.write("EXECUTION FLOW\n")
        for step in kf["execution_flow"]:
            f.write(f"  {step}\n")
        f.write("\n")
        
        f.write("IOCs\n")
        iocs = kf["iocs"]
        for k, v in iocs.items():
            f.write(f"  {k}: {v}\n")
        f.write("\n")
        
        f.write("GENERATED FILES\n")
        gf = results["generated_files"]
        for k, v in gf.items():
            f.write(f"  {k}: {v}\n")
        f.write("\n")
        
        f.write("NEXT STEPS\n")
        ns = results["next_steps"]
        for a in ns["recommended_actions"]:
            f.write(f"  {a}\n")
        f.write("\n")
        
        f.write("ADDITIONAL TOOLS NEEDED\n")
        for t in ns["additional_tools_needed"]:
            f.write(f"  {t}\n")
    
    print(f"[+] Summary checkpoint saved to {out_file}")
    print(f"[+] Human-readable summary saved to {summary_file}")

if __name__ == "__main__":
    main()