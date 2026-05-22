#!/usr/bin/env python3
"""
Search for the Bitcoin miner wallet address by:
1. Searching for RC4 keys and encrypted config in embedded_01.bin
2. Trying to decrypt config blobs using RC4 with candidate keys
3. Looking for JSON config structure after decryption
"""

import pefile
import re
import struct
import json
import hashlib
import math
from collections import Counter

DROPPER = "/home/kali/Downloads/sandbox/findings/data/embedded_pes/embedded_01.bin"
MINER = "/home/kali/Downloads/sandbox/findings/data/embedded_pes/embedded_00.bin"

def rc4_decrypt(key, data):
    """RC4 stream cipher decryption"""
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    
    i = j = 0
    result = bytearray(len(data))
    for k in range(len(data)):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        result[k] = data[k] ^ S[(S[i] + S[j]) % 256]
    return bytes(result)

def is_printable_config(data, min_ratio=0.7):
    """Check if data looks like printable config (JSON/text)"""
    if len(data) == 0:
        return False
    printable = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(data) >= min_ratio

def entropy(data):
    if len(data) == 0:
        return 0
    counter = Counter(data)
    length = len(data)
    return -sum((count/length) * math.log2(count/length) for count in counter.values())

# ============================================================
# Approach 1: Search .data section for encrypted config blobs
# ============================================================
print("[*] Approach 1: Scanning .data section for RC4-encrypted config...")
pe = pefile.PE(DROPPER)

for s in pe.sections:
    name = s.Name.rstrip(b'\x00').decode('ascii', errors='replace')
    if name == '.data':
        data = s.get_data()
        print(f"  .data size: {len(data)} bytes, entropy: {entropy(data):.2f}")
        
        # Find regions with moderate entropy (encrypted config, not too random, not too uniform)
        # Scan in 256-byte blocks
        interesting_blocks = []
        for offset in range(0, len(data) - 256, 64):
            block = data[offset:offset+256]
            ent = entropy(block)
            if 3.0 < ent < 7.5:  # Medium entropy = possibly encrypted
                nz = sum(1 for b in block if b != 0)
                if nz > 32:  # Not all zeros
                    interesting_blocks.append((offset, ent, nz))
        
        print(f"  Found {len(interesting_blocks)} interesting blocks")
        
        # For each interesting block, try RC4 with nearby data as key
        # The key is likely stored right before or after the encrypted config
        for offset, ent, nz in interesting_blocks[:30]:
            block = data[offset:offset+512]
            
            # Try various key sources:
            # 1. Bytes before the block (16 or 32 bytes)
            for key_len in [8, 16, 32]:
                if offset >= key_len:
                    key = data[offset-key_len:offset]
                    if all(b == 0 for b in key):
                        continue
                    decrypted = rc4_decrypt(key, block)
                    if is_printable_config(decrypted[:64], 0.6):
                        text = decrypted[:100].decode('ascii', errors='replace')
                        if any(kw in text.lower() for kw in ['pool', 'url', 'stratum', 'wallet', 'coin', 'algo', 'json', 'http', 'login', 'pass', 'user', '{']):
                            print(f"  *** DECRYPTED CONFIG at .data+0x{offset:x} with key at 0x{offset-key_len:x}:")
                            print(f"      {text}")
            
            # 2. Bytes after the block
            for key_len in [8, 16, 32]:
                key_start = offset + 512
                if key_start + key_len < len(data):
                    key = data[key_start:key_start+key_len]
                    if all(b == 0 for b in key):
                        continue
                    decrypted = rc4_decrypt(key, block)
                    if is_printable_config(decrypted[:64], 0.6):
                        text = decrypted[:100].decode('ascii', errors='replace')
                        if any(kw in text.lower() for kw in ['pool', 'url', 'stratum', 'wallet', 'coin', 'algo', 'json', 'http', 'login', 'pass', 'user', '{']):
                            print(f"  *** DECRYPTED CONFIG at .data+0x{offset:x} with key at 0x{key_start:x}:")
                            print(f"      {text}")

# ============================================================
# Approach 2: Search for known XMRig-style JSON config patterns
# in the full binary by trying RC4 with all short keys
# ============================================================
print("\n[*] Approach 2: Searching for JSON config in binary with brute-force RC4 keys...")

with open(DROPPER, 'rb') as f:
    full_data = f.read()

# Look for "pools" or "{" followed by JSON-like structure
# First, try to find the config by looking for blocks that decrypt to JSON with short keys

# The wlogz.dat is only 32 bytes - it might be just a key/hash, not the full config
# The full config is likely embedded in the binary and decrypted at runtime

# Let's search for specific patterns in .rdata that could be the encrypted config
pe2 = pefile.PE(DROPPER)
for s in pe2.sections:
    name = s.Name.rstrip(b'\x00').decode('ascii', errors='replace')
    if name == '.rdata':
        rdata = s.get_data()
        
        # The config in XMRig-style miners is typically JSON like:
        # {"pools":[{"url":"stratum+tcp://pool:port","user":"WALLET","pass":"x","coin":"monero"}]}
        # It would be RC4 encrypted. Let's look for blocks of ~200-500 bytes 
        # with moderate-high entropy
        
        # Find areas after the wide strings we identified (near wlogz.dat)
        # The config string references were at .rdata+0x1527c0-0x152b48
        # Search nearby for encrypted config data
        
        # Try every offset in a range near the config strings
        search_start = 0x152000
        search_end = min(0x153500, len(rdata))
        
        print(f"  Searching .rdata 0x{search_start:x}-0x{search_end:x} for RC4-encrypted config...")
        
        for offset in range(search_start, search_end - 16, 1):
            # Try short keys (common in malware)
            for key_val in range(256):
                key = bytes([key_val])
                block = rdata[offset:offset+100]
                decrypted = rc4_decrypt(key, block)
                if b'pools' in decrypted or b'stratum' in decrypted or b'wallet' in decrypted:
                    print(f"  *** FOUND at .rdata+0x{offset:x} with single-byte key 0x{key_val:02x}:")
                    print(f"      {decrypted[:200]}")
                    break

pe.close()
pe2.close()

print("\n[*] Approach 3: Checking if config is constructed dynamically (stack strings)...")
# The strings "login", "pass", "proxy", "url" found as narrow strings suggest
# the config JSON keys are constructed on the stack or in heap at runtime
# This means the wallet address is likely also constructed dynamically

# Let's check the VT relationships for the svctrl64.exe to find related samples
# that might have the config in cleartext

print("\n[*] Checking VT for related samples with extracted config...")
# Search VT for the family to find similar samples with known configs
import urllib.request
url = "https://www.virustotal.com/api/v3/files/ec860277d21159deb084b7849149a3700d98dc42d7d69e2e3acceed6dbe3158e/related_comments"
req = urllib.request.Request(url, headers={"x-apikey": "d3a82556c8c402e6d13fa98bfa01f009dc660b749ba15e95f46cd49031739e87"})
try:
    resp = urllib.request.urlopen(req, timeout=10)
    comments = json.loads(resp.read())
    for c in comments.get('data', [])[:5]:
        print(f"  Comment: {c.get('attributes', {}).get('text', 'N/A')[:200]}")
except:
    print("  No comments or error")

print("\n[+] Done searching. If wallet not found, it is likely constructed at runtime from obfuscated stackstrings.")
