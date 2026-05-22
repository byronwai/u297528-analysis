#!/usr/bin/env python3
"""
Extract embedded PE files from the decrypted payload's .rdata section.
Also extract strings, network indicators, and classify each embedded file.
"""

import pefile
import struct
import os
import hashlib
import json
import re
import math
from collections import Counter

PAYLOAD = "/home/kali/Downloads/sandbox/findings/data/decrypted_payload.exe"
OUTDIR = "/home/kali/Downloads/sandbox/findings/data/embedded_pes"

os.makedirs(OUTDIR, exist_ok=True)

def entropy(data):
    if len(data) == 0:
        return 0
    counter = Counter(data)
    length = len(data)
    return -sum((count/length) * math.log2(count/length) for count in counter.values())

def extract_strings(data, min_len=6):
    """Extract ASCII and wide strings from binary data"""
    ascii_strings = re.findall(b'[\x20-\x7e]{%d,}' % min_len, data)
    wide_strings = re.findall(b'(?:[\x20-\x7e]\x00){%d,}' % min_len, data)
    result = []
    for s in ascii_strings:
        result.append(s.decode('ascii', errors='replace'))
    for s in wide_strings:
        result.append(s.decode('utf-16-le', errors='replace'))
    return result

def find_pe_files(data):
    """Find all valid PE files within a data blob"""
    pes = []
    pos = 0
    while True:
        pos = data.find(b'MZ', pos)
        if pos == -1:
            break
        # Validate PE header
        if pos + 0x40 < len(data):
            pe_offset_bytes = data[pos + 0x3c:pos + 0x40]
            if len(pe_offset_bytes) == 4:
                pe_off = struct.unpack_from('<I', pe_offset_bytes)[0]
                if 0x40 <= pe_off < 0x1000 and pos + pe_off + 4 <= len(data):
                    if data[pos + pe_off:pos + pe_off + 4] == b'PE\x00\x00':
                        pes.append(pos)
        pos += 1
    return pes

# Load the decrypted payload
print("[*] Loading decrypted payload...")
with open(PAYLOAD, 'rb') as f:
    payload_data = f.read()

print(f"[+] Payload size: {len(payload_data)} bytes ({len(payload_data)/1024/1024:.2f} MB)")

# Parse with pefile
pe = pefile.PE(data=payload_data)

# ============================================================
# 1. Extract .rdata section data
# ============================================================
rdata = None
for s in pe.sections:
    if s.Name.rstrip(b'\x00') == b'.rdata':
        rdata = s.get_data()
        rdata_va = s.VirtualAddress
        rdata_size = s.Misc_VirtualSize
        print(f"[+] .rdata: VA=0x{rdata_va:x}, Size={len(rdata)} bytes ({len(rdata)/1024/1024:.1f} MB)")
        break

if not rdata:
    print("[-] .rdata section not found!")
    exit(1)

# ============================================================
# 2. Find all embedded PE files in .rdata
# ============================================================
print("\n[*] Scanning for embedded PE files in .rdata...")
pe_offsets = find_pe_files(rdata)
print(f"[+] Found {len(pe_offsets)} valid PE signatures in .rdata")

embedded_info = []

for idx, offset in enumerate(pe_offsets):
    # Estimate the size: from this PE to the next one (or end of section)
    if idx + 1 < len(pe_offsets):
        est_size = pe_offsets[idx + 1] - offset
    else:
        est_size = len(rdata) - offset
    
    # Limit to reasonable size (max 10MB per embedded file)
    est_size = min(est_size, 10 * 1024 * 1024)
    pe_data = rdata[offset:offset + est_size]
    
    # Try to parse with pefile to get exact size
    try:
        inner_pe = pefile.PE(data=pe_data)
        # Calculate actual PE size from sections
        actual_size = 0
        for s in inner_pe.sections:
            end = s.PointerToRawData + s.SizeOfRawData
            if end > actual_size:
                actual_size = end
        # Also include headers
        header_size = inner_pe.OPTIONAL_HEADER.SizeOfHeaders
        actual_size = max(actual_size, header_size)
        
        if actual_size > 0 and actual_size < est_size:
            pe_data = pe_data[:actual_size]
            est_size = actual_size
        
        machine = inner_pe.FILE_HEADER.Machine
        sections = inner_pe.FILE_HEADER.NumberOfSections
        timestamp = inner_pe.FILE_HEADER.TimeDateStamp
        subsystem = inner_pe.OPTIONAL_HEADER.Subsystem if hasattr(inner_pe.OPTIONAL_HEADER, 'Subsystem') else 0
        
        # Get imports
        imports = []
        if hasattr(inner_pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in inner_pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('ascii', errors='replace')
                func_names = []
                for imp in entry.imports:
                    if imp.name:
                        func_names.append(imp.name.decode('ascii', errors='replace'))
                    else:
                        func_names.append(f"ordinal_{imp.ordinal}")
                imports.append({"dll": dll_name, "functions": func_names[:10], "total": len(func_names)})
        
        # Get exports
        exports = []
        if hasattr(inner_pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in inner_pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    exports.append(exp.name.decode())
        
        inner_pe.close()
        
        machine_str = {0x14c: "x86", 0x8664: "x86-64", 0xAA64: "ARM64"}.get(machine, f"0x{machine:x}")
        
    except Exception as e:
        machine = 0
        sections = 0
        machine_str = "unknown"
        imports = []
        exports = []
        timestamp = 0
        subsystem = 0
    
    # Calculate hashes
    md5 = hashlib.md5(pe_data).hexdigest()
    sha256 = hashlib.sha256(pe_data).hexdigest()
    ent = entropy(pe_data[:min(4096, len(pe_data))])
    
    # Extract strings
    strings = extract_strings(pe_data[:min(0x10000, len(pe_data))])
    interesting_strings = [s for s in strings if len(s) > 8 and any(kw in s.lower() for kw in 
        ['http', 'https', '.com', '.net', '.org', '.exe', '.dll', 'mutex', 'registry', 'crypto',
         'bitcoin', 'miner', 'pool', 'stratum', 'wallet', 'config', 'password', 'cmd',
         'powershell', 'rundll', 'inject', 'hook', 'keylog', 'screen', 'download', 'upload'])]
    
    # Network indicators
    ips = re.findall(rb'\b(?:\d{1,3}\.){3}\d{1,3}\b', pe_data[:min(0x100000, len(pe_data))])
    urls = re.findall(rb'https?://[^\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0b\x0c\x0e\x0f\x10-\x1f"]{6,}', 
                       pe_data[:min(0x100000, len(pe_data))])
    domains = re.findall(rb'[a-zA-Z0-9][-a-zA-Z0-9]{0,62}\.(com|net|org|io|xyz|top|ru|cn|cc|tk|ml|ga|cf|gq)', 
                          pe_data[:min(0x100000, len(pe_data))])
    
    # Save embedded PE
    filename = f"embedded_{idx:02d}.bin"
    filepath = os.path.join(OUTDIR, filename)
    with open(filepath, 'wb') as f:
        f.write(pe_data)
    
    info = {
        "index": idx,
        "offset": f"0x{offset:x}",
        "rva": f"0x{rdata_va + offset:x}",
        "size": len(pe_data),
        "md5": md5,
        "sha256": sha256,
        "entropy": round(ent, 2),
        "machine": machine_str,
        "sections": sections,
        "timestamp": f"0x{timestamp:x}",
        "subsystem": subsystem,
        "imports": imports,
        "exports": exports,
        "interesting_strings": interesting_strings[:20],
        "network": {
            "ips": [ip.decode() for ip in set(ips)][:10],
            "urls": [url.decode('ascii', errors='replace') for url in set(urls)][:10],
            "domains": [d.decode() for d, _ in re.findall(rb'([a-zA-Z0-9][-a-zA-Z0-9]{0,62}\.(com|net|org|io|xyz|top|ru|cn|cc))', 
                         pe_data[:min(0x100000, len(pe_data))])][:10]
        },
        "file": filename
    }
    embedded_info.append(info)
    
    print(f"\n  [{idx:02d}] Offset=0x{offset:x} Size={len(pe_data):,} bytes "
          f"Machine={machine_str} Sections={sections} Entropy={ent:.2f}")
    print(f"       MD5={md5}")
    if imports:
        for imp in imports[:3]:
            print(f"       Import: {imp['dll']} ({imp['total']} funcs)")
    if interesting_strings:
        print(f"       Interesting strings: {interesting_strings[:3]}")
    if info['network']['ips'] or info['network']['urls'] or info['network']['domains']:
        print(f"       Network: IPs={info['network']['ips'][:3]} URLs={info['network']['urls'][:3]} Domains={info['network']['domains'][:3]}")

# ============================================================
# 3. Also scan the full decrypted payload for network indicators
# ============================================================
print("\n\n[*] Extracting network indicators from full decrypted payload...")

all_ips = list(set(ip.decode() for ip in re.findall(rb'\b(?:\d{1,3}\.){3}\d{1,3}\b', payload_data)))
# Filter out obvious non-C2 IPs
private_ips = {'10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.',
               '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.',
               '192.168.', '127.', '0.0.', '255.255.255.255'}
public_ips = [ip for ip in all_ips if not any(ip.startswith(p) for p in private_ips)]

all_urls = list(set(url.decode('ascii', errors='replace') for url in 
              re.findall(rb'https?://[^\x00-\x1f"]{6,}', payload_data)))
all_domains = list(set(d.decode() for d, _ in 
               re.findall(rb'([a-zA-Z0-9][-a-zA-Z0-9]{0,62}\.(com|net|org|io|xyz|top|ru|cn|cc|pw|me|info|biz))', payload_data)))

# Extract wide strings (UTF-16) for file paths
wide_paths = re.findall(rb'([A-Z]:\\[^\x00]{3,}\x00)', payload_data[:0x100000])
file_paths = [p.decode('utf-16-le', errors='replace').rstrip('\x00') for p in wide_paths[:20]]

# Extract mutex names
mutex_strings = [s for s in extract_strings(payload_data[:0x100000]) if 'mutex' in s.lower() or 'Global\\' in s or 'Local\\' in s]

# Extract registry keys
reg_keys = [s for s in extract_strings(payload_data[:0x100000]) if any(k in s for k in 
            ['SOFTWARE\\', 'HKEY_', 'CurrentVersion\\Run', 'CurrentVersion\\Explorer'])]

network_indicators = {
    "public_ips": public_ips[:20],
    "all_urls": all_urls[:20],
    "domains": all_domains[:20],
    "file_paths": file_paths[:20],
    "mutex_names": mutex_strings[:10],
    "registry_keys": reg_keys[:10]
}

print(f"[+] Public IPs: {public_ips[:10]}")
print(f"[+] URLs: {all_urls[:10]}")
print(f"[+] Domains: {all_domains[:10]}")
print(f"[+] File paths: {file_paths[:5]}")
print(f"[+] Mutex names: {mutex_strings[:5]}")
print(f"[+] Registry keys: {reg_keys[:5]}")

# ============================================================
# 4. Save all results
# ============================================================
results = {
    "embedded_pe_count": len(embedded_info),
    "embedded_pes": embedded_info,
    "network_indicators": network_indicators
}

with open("/home/kali/Downloads/sandbox/findings/data/embedded_analysis.json", 'w') as f:
    json.dump(results, f, indent=2, default=str)

print(f"\n[+] Saved embedded_analysis.json")
print(f"[+] Extracted {len(embedded_info)} embedded PE files to {OUTDIR}/")
print(f"[+] Done!")
